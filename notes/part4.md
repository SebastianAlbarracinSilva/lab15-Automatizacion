# Parte 4: verificacion y pregunta

## Verificacion del audit log
Todas las llamadas a herramientas externas pasan por run_logged(); ninguna etapa llama a subprocess.run
directamente. En las tres ejecuciones de sample_output/ cada linea RUN tiene su linea OK o FAIL
(ip: 3/3, domain: 6/6, failure_test: 7/7), y cada etapa tiene STAGE start/end. failure_test se ejecuto
con PATH vacio: las tres etapas fallan, se registran como FAIL y la herramienta igual escribe
results.json y report.md (cada etapa falla de forma independiente).

Observacion: en modo IP, --top-ports 100 solo encontro el 22; 210, 555 y 888 estan abiertos pero no
estan entre los 100 puertos mas comunes. Por eso el informe aclara que un puerto no listado no esta
necesariamente cerrado, y recon.py acepta --ports para ampliar el rango.

## Pregunta: reconocimiento activo vs. pasivo
Atacante: el reconocimiento activo (recon.py) da datos actuales y verificados: lo que el objetivo
responde hoy, con versiones exactas, y puede llegar a puertos y servicios que nadie ha indexado. A cambio
es lento, necesita conectividad con el objetivo y deja huella: cada sonda aparece en firewall, IDS,
registros de flujo y logs de los servicios, y la IP de origen queda registrada. El pasivo (Shodan) es
instantaneo y no envia ni un paquete al objetivo, pero los datos pueden estar desactualizados, solo cubre
lo expuesto a Internet y lo que Shodan decidio escanear, y depende de los limites de la API.

Defensor con monitoreo: el pasivo es mucho mas dificil de detectar, en la practica indetectable en el
momento, porque la consulta ocurre entre el atacante y la base de datos de Shodan. La unica huella en el
objetivo es el escaneo previo de Shodan, que se ve como ruido de fondo y no se puede asociar a un atacante
concreto. El activo es detectable: rafagas de SYN, sondas de -sV y peticiones HEAD siguen patrones
conocidos por los IDS y se pueden atribuir a una IP.

Cuando usar cada uno: el pasivo para la fase inicial y discreta (mapear la superficie expuesta antes de
tocar nada), cuando no hay autorizacion para enviar trafico, o para que un defensor vea su propia
exposicion como la ve Internet. El activo cuando hay autorizacion y alcance definidos (pentest), cuando se
necesitan datos actuales y exactos, o para redes internas que ningun servicio pasivo indexa, como la red
de este laboratorio.
