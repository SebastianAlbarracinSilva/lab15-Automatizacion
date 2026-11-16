# Parte 2: resultados

- `nmap -sV --open -oX scan.xml 192.168.216.128` (sin -p) reporto solo 22, 555 y 888: nmap escanea por defecto
  los 1000 puertos mas frecuentes y el 210 no esta en esa lista. `nmap -p 210` confirmo que estaba abierto.
  Se re-escaneo con `-p 1-1024` y aparecieron los 4 puertos. Es el mismo principio de la Parte 1:
  "no detectado" no es "cerrado"; un puerto que no se probo no tiene estado.
- ssh-keyscan devolvio 4 tipos de llave: ecdsa-sha2-nistp256, ssh-rsa, ssh-ed25519 y ssh-mldsa44-ed25519
  (hibrida post-cuantica, OpenSSH 10.6). ssh_host_key_type se guarda como lista para no perder ninguna.
- Prueba de fallo: con `systemctl stop ssh`, parse_scan.py registra ssh_host_key_type = null y
  ssh_keyscan_error, y termina sin excepcion.

## Pregunta
Un banner con version convierte el ataque en una busqueda: con "Apache httpd 2.4.54" el atacante consulta
NVD/CVE o searchsploit por ese producto y version, obtiene los CVE que lo afectan, su severidad (CVSS) y si
hay exploits publicos, y prioriza ese host sin enviar mas pruebas. Un servidor sin version obliga al atacante
a hacer fingerprinting por comportamiento, que es mas lento, mas ruidoso (mas probable que lo detecte un IDS)
y menos preciso. La diferencia relevante es de informacion, no de seguridad: ocultar la version no corrige
ninguna vulnerabilidad, porque el servicio sigue siendo el mismo y a menudo se puede identificar igual. Y al
reves, una version visible puede exagerar el riesgo, porque las distribuciones aplican parches de seguridad
(backports) sin cambiar el numero de version; por eso un "OpenSSH 10.6p1 Debian 1" debe contrastarse con el
estado de parches de la distribucion, no solo con la version upstream.
