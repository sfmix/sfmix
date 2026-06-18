---
title: "stats 📊"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-sf-night.jpg"
---

## public grafana dashboards 📊

SFMIX uses sFlow to sample exchange traffic metadata, including peer-to-peer volume metrics. packet payloads are never captured or inspected (we're not nosy 🤫). the stack is sFlow-RT, Prometheus, and [Grafana](https://grafana.com/).

- [overall traffic dashboard](https://grafana.sfmix.org/public-dashboards/7dedd014679f4c798124748a24e9f5ef) 📈
- [traffic weathermap](https://grafana.sfmix.org/public-dashboards/e93a968eb538461da4c6ada750b33495) 🗺️
