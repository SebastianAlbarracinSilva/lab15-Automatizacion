# Parte 1: resultados

Objetivo: 192.168.216.128 (puertos 1-1024). Puertos abiertos esperados (answer key): 22, 210, 555, 888.

| Version            | Concurrencia | Tiempo (s) | Abiertos encontrados | Perdidos | Errores |
|--------------------|-------------:|-----------:|----------------------|----------|--------:|
| Secuencial         | 1            | X.XXX      | 22, 210, 555, 888    | -        | -       |
| ThreadPoolExecutor | 50           | 0.19       | 22, 210, 555, 888    | -        | -       |
| ThreadPoolExecutor | 200          | 0.21       | 22, 210, 555, 888    | -        | -       |
| ThreadPoolExecutor | 500          | 0.20       | 22, 210, 555, 888    | -        | -       |
| asyncio + Semaphore| 50           | 0.07       | 22, 210, 555, 888    | -        | 0       |
| asyncio + Semaphore| 200          | 0.07       | 22, 210, 555, 888    | -        | 0       |
| asyncio + Semaphore| 500          | 0.08       | 22, 210, 555, 888    | -        | 0       |
| asyncio + Semaphore| 2000         | 0.08       | 22, 210, 555, 888    | -        | 6 (EMFILE) |
| asyncio, 1-5000    | 2000         | 0.16       | 22, 210, 555, 888    | -        | 3982 (EMFILE) |

Las diferencias de tiempo son pequenas porque el objetivo es la propia maquina: los puertos cerrados
responden RST al instante, asi que no hay espera que solapar y el costo de crear hilos domina.
asyncio es mas rapido que los hilos porque no crea hilos del sistema operativo.

Comprobacion del analista: comparando scan_rate200.json y scan_rate2000.json con el answer key,
ninguna de las dos ejecuciones perdio puertos abiertos, pero la de rate 2000 dejo 6 puertos sin resultado (EMFILE).
