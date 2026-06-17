---
title: "Looking Glass"
layout: "video-header"
video: "video/participants-bg.mp4"
mobile_image: "img/mobile-fiber-light.jpg"
---

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
