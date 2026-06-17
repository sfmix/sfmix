---
title: "Servidores de rutas"
layout: "video-header"
video: "video/route-servers-bg.mp4"
mobile_image: "img/mobile-fiber-light.jpg"
---

Los servidores de rutas de SFMIX permiten el intercambio multilateral de tráfico mediante una única sesión BGP (idealmente dos para redundancia). El servidor de rutas agrega y redistribuye las rutas de los participantes, de modo que puedes empezar a intercambiar tráfico de inmediato sin negociar sesiones bilaterales.

Aun así, se recomienda el intercambio directo; el uso del servidor de rutas es opcional. La configuración se genera con [arouteserver](https://github.com/pierky/arouteserver).

Para mayor resiliencia, SFMIX ejecuta dos pilas distintas:

- **BIRD** sobre Linux, con Routinator para RPKI
- **OpenBGPD** sobre OpenBSD, con [rpki-client](https://www.rpki-client.org/) para RPKI

Resúmenes de configuración: [BIRD/Linux](https://lg.sfmix.org/rs-linux.sfmix.org.summary.html) · [OpenBGPD/OpenBSD](https://lg.sfmix.org/rs-openbsd.sfmix.org.summary.html)

Usa el [explorador de rutas](https://alice.sfmix.org/) ([Alice LG](https://github.com/alice-lg/alice-lg)) para depurar el filtrado de rutas. SFMIX implementa, siempre que es posible, las [Large BGP Communities estandarizadas por Euro-IX](https://www.euro-ix.net/en/forixps/large-bgp-communities/).

## Seguridad del enrutamiento

Los servidores de rutas filtran los anuncios en función de RPKI, IRR y límites de prefijos máximos (de PeeringDB). Las rutas RPKI Invalid se rechazan; las rutas RPKI Unknown se permiten actualmente.

SFMIX publica el as-set de IRR ["AS-SFMIX-RS"](https://irrexplorer.nlnog.net/as-set/AS-SFMIX-RS) a través de ARIN para ayudar a los participantes a crear filtros basados en IRR.

## Información de conexión

<div class="rs-cards">
  <div class="rs-card">
    <h4>Servidor de rutas n.º 1 — BIRD / Linux</h4>
    <dl>
      <dt>ASN</dt><dd>63055</dd>
      <dt>IPv4</dt><dd><code>206.197.187.253</code></dd>
      <dt>IPv6</dt><dd><code>2001:504:30::ba06:3055:1</code></dd>
    </dl>
  </div>
  <div class="rs-card">
    <h4>Servidor de rutas n.º 2 — OpenBGPD / OpenBSD</h4>
    <dl>
      <dt>ASN</dt><dd>63055</dd>
      <dt>IPv4</dt><dd><code>206.197.187.254</code></dd>
      <dt>IPv6</dt><dd><code>2001:504:30::ba06:3055:2</code></dd>
    </dl>
  </div>
</div>

## BGP Communities para el control de propagación

Controla cómo se propagan tus prefijos a otros participantes:

| Cadena de community | Función |
|------------------|----------|
| 63055:63055 | Enviar prefijos a todos los demás participantes del servidor de rutas |
| 63055:*ASN* | Enviar el prefijo solo al participante del servidor de rutas con un ASN específico |
| 0:*ASN* | No enviar el prefijo al participante del servidor de rutas con un ASN específico |
| 0:63055 | No enviar el prefijo a ningún otro participante del servidor de rutas |
| 63055:65281 | Enviar prefijos con el atributo NO_EXPORT |

## BGP Communities para metadatos informativos

Las communities de metadatos indican dónde se aprendieron las rutas y los atributos de los participantes. Consulta [Ubicaciones](/locations/) para ver los códigos de sede.

## BGP Communities para explicar el filtrado

Las rutas filtradas no se descartan: se etiquetan internamente y se excluyen de la redistribución. Esto permite a los operadores usar el [explorador de rutas](https://alice.sfmix.org/) para diagnosticar por qué se filtran o aceptan las rutas.
