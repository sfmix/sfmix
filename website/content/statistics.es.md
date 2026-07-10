---
title: "Estadísticas"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Estadísticas y mapas en vivo

SFMIX usa sFlow para muestrear los metadatos del tráfico del intercambio, incluidas las métricas de volumen de par a par. Las cargas útiles de los paquetes nunca se capturan ni se inspeccionan. El tráfico se recopila con sFlow-RT y Prometheus, y puedes explorarlo de dos maneras: mediante nuestros propios mapas interactivos en vivo o mediante los paneles públicos de [Grafana](https://grafana.com/).

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://grafana.sfmix.org/public-dashboards/7dedd014679f4c798124748a24e9f5ef" title="Panel de tráfico general" desc="Rendimiento agregado del intercambio, picos y tendencias históricas." >}}

{{< stat-card icon="🗺️" url="/es/weathermap/" external="false" title="Mapa de calor del tráfico" desc="El clásico weathermap, renovado: cada enlace del backbone coloreado según su utilización en vivo. Desplázate, haz zoom y pulsa cualquier enlace para ver sus tasas y una gráfica de 24 horas." >}}

{{< stat-card icon="🚇" url="/es/network-map/" external="false" title="Mapa de red interactivo" desc="Un mapa estilo metro de la red, coloreado según el tráfico en vivo. Amplía desde las metrópolis hasta los sitios." >}}

</div>
