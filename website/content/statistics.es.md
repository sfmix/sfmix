---
title: "Estadísticas y Looking Glass"
aliases: ["/looking-glass/"]
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## Estadísticas y mapas en vivo

SFMIX usa sFlow para muestrear los metadatos del tráfico del intercambio, incluidas las métricas de volumen de par a par. Las cargas útiles de los paquetes nunca se capturan ni se inspeccionan. El tráfico se recopila con sFlow-RT y Prometheus, y puedes explorarlo mediante nuestros paneles en vivo y mapas interactivos.

<div class="stat-cta-grid">

{{< stat-card icon="📈" url="https://portal.sfmix.org/statistics/" title="Panel de tráfico general" desc="Rendimiento agregado del intercambio, picos y tendencias históricas." >}}

{{< stat-card icon="🗺️" url="/es/weathermap/" external="false" title="Mapa de calor del tráfico" desc="El clásico weathermap, renovado: cada enlace del backbone coloreado según su utilización en vivo. Desplázate, haz zoom y pulsa cualquier enlace para ver sus tasas y una gráfica de 24 horas." >}}

{{< stat-card icon="🚇" url="/es/network-map/" external="false" title="Mapa de red interactivo" desc="Un mapa estilo metro de la red, coloreado según el tráfico en vivo. Amplía desde las metrópolis hasta los sitios." >}}

</div>

## Looking Glass

Todos los participantes deben intercambiar tráfico con el Looking Glass de SFMIX. Cumple varios propósitos:

- Validar la configuración de tu router al conectarte por primera vez
- Probar cambios de configuración contra un par de bajo impacto, con una vista de autoservicio de lo que el LG ve desde tu lado
- Visibilidad pública de qué prefijos están presentes en el intercambio
- Comprobación rápida de alcanzabilidad para los operadores de SFMIX

## VLAN de cuarentena

Un Looking Glass paralelo se ejecuta en la VLAN de cuarentena con las mismas direcciones que producción. Los nuevos participantes pueden probar su configuración de Ethernet, IP y BGP de forma segura antes de unirse a la LAN de intercambio de producción.

## Información de conexión BGP

| Parámetro | Valor |
|-----------|-------|
| ASN | 12276 |
| IPv4 | 206.197.187.1 |
| IPv6 | 2001:504:30::ba01:2276:1 |

## Explorador de rutas

SFMIX ejecuta [Alice LG](https://github.com/alice-lg/alice-lg) como explorador de rutas: una única interfaz para la información de enrutamiento del Looking Glass y de los servidores de rutas.

**[alice.sfmix.org](https://alice.sfmix.org/)**
