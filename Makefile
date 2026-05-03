.PHONY: setup attack cleanup test

# Levanta el laboratorio vulnerable en Docker
setup:
	@echo "Levantando el laboratorio de víctimas en Docker..."
	docker-compose -f docker-compose-lab.yml up -d
	@echo "Laboratorio activo. Revisa las IPs con 'docker ps'."

# Lanza el ataque del gusano en tiempo real con CLI interactivo
attack:
	@echo "Iniciando Wormy C2 y propagación (CLI interactivo)..."
	python3 worm_core.py -i

# Detiene el laboratorio y limpia la red
cleanup:
	@echo "Apagando el laboratorio y limpiando..."
	docker-compose -f docker-compose-lab.yml down
	@echo "Entorno limpio."

# Ejecuta el script enterprise simulado (dry-run)
enterprise-dry:
	sudo bash scripts/deploy_kali.sh
