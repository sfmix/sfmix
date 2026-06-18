---
title: "Guía de conexión"
layout: "video-header"
video: "video/connection-guide-bg.mp4"
mobile_image: "img/mobile-fiber-cables.jpg"
---

<p class="lead">¿Quieres conectarte a SFMIX? Así se hace.</p>

## Descripción general

1. Revisa los precios y requisitos a continuación
2. Escribe a [tech-c@sfmix.org](mailto:tech-c@sfmix.org) indicando la velocidad deseada y la [ubicación](/locations/); confirmaremos la disponibilidad de puertos

   > **Consejo:** Usa el asunto "New Connection Request – [Nombre de tu organización]" e incluye la URL de tu PeeringDB, la velocidad deseada y la ubicación preferida. Normalmente respondemos en un plazo de 1 a 2 días hábiles.

3. Completa la [solicitud de membresía](https://goo.gl/forms/fiqOIjCP7QHYUG3i1)
4. SFMIX emite una LOA/CFA para que solicites una interconexión con el operador del centro de datos
5. SFMIX asigna tus direcciones IPv4 e IPv6
6. Tu circuito se conecta a una **VLAN de cuarentena**, un entorno seguro para levantar tu enlace y validar la configuración antes de tocar producción
7. Una vez listo, SFMIX mueve tu puerto a la VLAN de intercambio de producción
8. ¡Comienza a intercambiar tráfico!

## Requisitos administrativos

### Precios

{{< pricing >}}

### Facturación

- Facturación anual (año natural); no hay opción mensual
- Solo en USD
- Pago (orden preferido): ACH, transferencia, cheque, tarjeta de crédito

## Requisitos logísticos

- Al menos un representante debe suscribirse a la [lista de correo sfmix-members](https://lists.sfmix.org/postorius/lists/sfmix-members.lists.sfmix.org/). Se recomiendan cuentas de rol. Escribe a [tech-c@sfmix.org](mailto:tech-c@sfmix.org) para suscribirte.
- Las conversaciones de la lista de correo son confidenciales para participantes, miembros y patrocinadores.
- SFMIX es operado por voluntarios. Todos los servicios son de mejor esfuerzo; no se implica ningún SLA.
- Los participantes pueden intercambiar tráfico en una única ubicación, independientemente del número de puertos. SFMIX es una infraestructura de intercambio, no una red de transporte.
- No se permite la suplantación de ARP/ICMPv6 ni la captura de tráfico.

## Requisitos técnicos

- **Solo fibra monomodo** — sin cobre ni fibra multimodo.
- Se requiere un ASN público asignado por un RIR ([RFC 1930](https://datatracker.ietf.org/doc/html/rfc1930), [RFC 6996](https://datatracker.ietf.org/doc/html/rfc6996)). No se permiten ASN privados.
- Se requiere una entrada de [PeeringDB](https://peeringdb.org/) mantenida.
- **Una dirección MAC por enlace lógico.** La seguridad de puertos permite 2 MAC de forma temporal para migraciones de routers, pero solo 1 a largo plazo.
- **Difusión permitida:** únicamente ARP e ICMPv6 ND. No se permiten RA, CDP, DHCP ni STP.
- **LLDP:** SFMIX transmite LLDP en todos los puertos de participantes, incluidos los niveles de potencia óptica recibida. Los participantes pueden transmitir LLDP, pero no es obligatorio.
- **La sesión BGP con el [Looking Glass](/looking-glass/) es obligatoria.** Se utiliza únicamente para depuración: no se redistribuyen rutas ni se intercambia tráfico.
- No propagues las subredes de intercambio de SFMIX (206.197.187.0/24, 2001:504:30::/64) más allá de tu router de borde. Usa ACL si es necesario.
- No se permiten rutas estáticas ni predeterminadas hacia otros participantes o recursos de SFMIX sin autorización.
- Se recomienda, pero no se exige, el intercambio con los [servidores de rutas](/route-servers/).

## Monitoreo de LLDP y potencia óptica

Los conmutadores de SFMIX transmiten [LLDP](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol) en cada puerto de participante. Además de la información estándar de LLDP (nombre del sistema, descripción del puerto), cada trama incluye la potencia óptica recibida medida por el transceptor del lado de SFMIX, codificada como un TLV de inventario [LLDP-MED](https://en.wikipedia.org/wiki/Link_Layer_Discovery_Protocol#LLDP-MED).

Esto te permite ver, desde tu propio router, qué tan bien está llegando tu luz de transmisión al conmutador de SFMIX, sin necesidad de contactarnos para obtener soporte.

### Qué se anuncia

El campo Asset ID de LLDP-MED transporta la potencia recibida en dBm:

- **Ejemplo de óptica de un solo carril:** `dBm:-2.05`
- **Ejemplo de óptica de múltiples carriles:** `dBm:-7.60/-8.20/-6.79/-6.52` (un valor por carril)

### Visualización de los datos

En **Arista EOS**:

```
switch# show lldp neighbors Ethernet1 detail | grep 'Asset ID'
  - LLDP-MED Inventory Asset ID TLV: "dBm:-2.05"
```

En **Linux** (lldpd):

```
$ lldpcli show neighbors
  LLDP-MED:
    Inventory:
      Asset ID:     dBm:-2.05
```

En **Juniper Junos**:

```
user@router> show lldp neighbors interface xe-0/0/0
```

En otras plataformas, busca TLV de inventario LLDP-MED o TLV definidos por la organización con OUI `00:12:BB`, subtipo 11.

### Interpretación de los valores

Los valores de potencia representan lo que el transceptor de SFMIX está recibiendo desde tu lado. Si observas valores que descienden hacia el umbral de sensibilidad del receptor del transceptor (normalmente alrededor de −14 dBm para LR4 y −22 dBm para ER4), puede que tu planta de fibra requiera atención. Un valor de `dBm:-40.00` o la ausencia de un TLV de Asset ID significa que no se detecta luz.

La potencia óptica vía LLDP se admite actualmente solo en los puertos de borde de Arista, lo que cubre prácticamente todos los puertos de intercambio en la actualidad. El agente que inyecta estos datos es de código abierto: [LldpDomAgent en GitHub](https://github.com/sfmix/sfmix/blob/main/scripts/arista_eos/LldpDomAgent).
