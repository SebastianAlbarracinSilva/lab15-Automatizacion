# Parte 3: pregunta

Una baseline global mezcla en una sola media y desviacion las horas pico (dia) y las horas valle (noche).
Eso tiene dos efectos: la media queda por encima de lo normal de noche y por debajo de lo normal de dia,
y la desviacion estandar se infla por la propia variacion diaria. Resultado: un pico nocturno que es
enorme para las 3 a.m. puede no superar el umbral (falso negativo), mientras que la hora pico normal de
cada dia puede superarlo (falso positivo). Ademas, la propia anomalia contamina la baseline: sube la media
y la desviacion, de modo que con n muestras el z maximo alcanzable es (n-1)/sqrt(n) (4.69 con 24 horas;
nuestro pico llego a 4.61).

Enfoque modificado: comparar cada hora contra la misma hora de dias anteriores (baseline por hora del
dia, y por dia de la semana si hay suficiente historia), por ejemplo las ultimas 2-4 semanas. Para cada
hora h: mediana y MAD de los conteos de la hora h en dias previos; alerta si
(conteo - mediana) / (1.4826 * MAD) > 3. La mediana y la MAD son robustas: un pico no las desplaza.
Alternativas: ventana movil (rolling window) o descomponer la serie en tendencia + estacionalidad
y aplicar el umbral solo al residuo. El umbral se ajusta contra el historial para controlar los falsos
positivos, porque los conteos de peticiones no son normales (tienen colas pesadas).
