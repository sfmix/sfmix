---
title: "Estadísticas"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Paneles públicos de Grafana

SFMIX usa sFlow para muestrear los metadatos del tráfico del intercambio, incluidas las métricas de volumen de par a par. Las cargas útiles de los paquetes nunca se capturan ni se inspeccionan. La pila está compuesta por sFlow-RT, Prometheus y [Grafana](https://grafana.com/).

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://grafana.sfmix.org/public-dashboards/7dedd014679f4c798124748a24e9f5ef" title="Panel de tráfico general" desc="Rendimiento agregado del intercambio, picos y tendencias históricas." >}}

{{< stat-card icon="🗺️" url="/weathermap/" external="false" title="Mapa de calor del tráfico" desc="Utilización en vivo por enlace en la red de conmutación de SFMIX." >}}

{{< stat-card icon="🚇" url="/es/network-map/" external="false" title="Mapa de red interactivo" desc="Un mapa estilo metro de la red, coloreado según el tráfico en vivo. Amplía desde las metrópolis hasta los sitios." >}}

</div>
