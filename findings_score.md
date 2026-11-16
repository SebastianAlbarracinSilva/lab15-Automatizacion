# Findings score: planted.json vs report.md

Detectados: **12/12** | Falsos positivos: **0**

## Elementos plantados

| Elemento plantado | Detectado | Detalle |
|---|---|---|
| Fuerza bruta desde 103.75.12.44 (48 fallos) | si | detectados 48 fallos |
| Fuerza bruta desde 91.240.118.7 (27 fallos) | si | detectados 27 fallos |
| 31 lineas 'invalid user' (test/oracle/admin1) | si | marcados como inexistentes: ['admin1', 'oracle', 'test'] |
| Login exitoso tras fallos desde 91.240.118.7 | si | Mar 15 23:50:00, 27 fallos previos |
| Pico de trafico a las 04:00 desde 198.51.100.77 | si | z~4.61 |
| sqli: `/?id=1'%20UNION%20SELECT%201,2,3--` | si | 2/2 IPs |
| path_traversal: `/admin/..%2f..%2f..%2fetc/passwd` | si | 2/2 IPs |
| xss: `/search?q=%3Cscript%3Ealert(1)%3C/script%3E` | si | 2/2 IPs |
| command_injection: `/cgi-bin/test.cgi?cmd=id%3Bcat%20/etc/passwd` | si | 2/2 IPs |
| path_traversal (custom): `/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd` | si | 2/2 IPs |
| sqli (custom): `/item?id=1%20UN/**/ION%20SEL/**/ECT%20user,password%20FROM%20users--` | si | 2/2 IPs |
| xss (custom): `/search?q=%3Csvg%20onload%3Dalert(1)%3E` | si | 2/2 IPs |

## Elementos del informe que no fueron plantados (falsos positivos)

Ninguno: todo lo reportado corresponde a algo plantado.

## Fallos del primer borrador y arreglos

- `/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd`: el primer borrador (regex de la teoria + un solo unquote) NO lo detecta. Causa: patron debil. Arreglo: doble codificacion: decodificar en bucle (hasta 3 rondas) antes de buscar.
- `/item?id=1%20UN/**/ION%20SEL/**/ECT%20user,password%20FROM%20users--`: el primer borrador (regex de la teoria + un solo unquote) NO lo detecta. Causa: patron debil. Arreglo: comentario SQL que parte la palabra: eliminar /**/ antes de buscar union...select.
- `/search?q=%3Csvg%20onload%3Dalert(1)%3E`: el primer borrador (regex de la teoria + un solo unquote) NO lo detecta. Causa: patron debil. Arreglo: XSS sin <script: agregar <svg, on<evento>=, javascript: e <iframe.
- auth.log: el patron sin `(?:invalid user )?` cuenta 98 fallos frente a 161; pierde 63 intentos contra cuentas inexistentes. Causa: patron debil. Arreglo: 'invalid user' opcional en el regex.
- access.log: el regex de linea de la teoria corta la ruta en el primer espacio. Arreglo preventivo: la ruta termina en ' HTTP/x.y"', no en el primer espacio.
- 3-sigma: el pico se detecto con z~4.61, cerca del maximo alcanzable (4.69) con 24 muestras. Limite del metodo, no del patron: con 10 horas o menos ningun pico supera 3 sigma. Mitigacion: baseline robusta (mediana/MAD) o comparacion contra la misma hora de dias anteriores.
