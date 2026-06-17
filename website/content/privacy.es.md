---
title: "Política de privacidad"
layout: "single"
---

SFMIX ("San Francisco Metropolitan Internet eXchange") es una cooperativa sin fines de lucro IRS 501(c)(12). Nos comprometemos con la transparencia respecto a los datos limitados que recopilamos y cómo los usamos.

## Qué recopilamos

### Información administrativa de los participantes

Cuando una organización se conecta a SFMIX, recopilamos la información básica de contacto y facturación necesaria para operar el intercambio:

- **Datos de contacto** — nombre, dirección de correo electrónico, número de teléfono y dirección postal de los contactos operativos y de facturación autorizados.
- **Datos de la organización** — nombre de la organización, ASN y registro de PeeringDB.

Esta información se utiliza únicamente para la coordinación operativa, la facturación y las notificaciones de servicio. No vendemos ni compartimos la información de contacto de los participantes con terceros.

### Datos de tráfico de red

SFMIX opera una infraestructura de conmutación compartida que reenvía paquetes entre los participantes. No inspeccionamos, almacenamos ni analizamos el contenido de los paquetes que transitan por el intercambio.

Sí recopilamos los siguientes datos operativos:

- **Contadores de interfaz** — recuentos agregados de paquetes y bytes en las interfaces de red de cara a los participantes, utilizados para la planificación de capacidad, la verificación de facturación y el monitoreo operativo.
- **Muestras de flujo** — muestras estadísticas de flujo recopiladas de la infraestructura de conmutación mediante protocolos como sFlow o IPFIX, utilizadas para generar matrices agregadas de tráfico de miembro a miembro y estadísticas de todo el intercambio. Estos protocolos capturan encabezados de paquetes (normalmente los primeros 128 bytes) a una tasa de muestreo definida; no capturan las cargas útiles completas de los paquetes.

Las estadísticas de tráfico derivadas de estos datos pueden mostrarse de forma agregada en nuestra página de [Estadísticas](/statistics/) o compartirse con participantes individuales en relación con su propio tráfico.

### Tu tráfico es asunto tuyo

Seamos claros: **no nos importa qué envíes a través del intercambio.** SFMIX es una plataforma abierta para transportar bits, no un foro moderado. Nuestra labor es reenviar tus paquetes al otro lado, no tener opiniones sobre ellos.

Dicho esto, aplicamos algunas tareas de mantenimiento sensatas para mantener la infraestructura compartida funcionando sin problemas:

- **En la capa 3 (IP)** — Nuestras plataformas de servidores de rutas validan las rutas mediante IRR, RPKI y (con el tiempo) ASPA para ayudar a los participantes a tomar buenas decisiones de enrutamiento. Esto es filtrado de *información de enrutamiento*, no del tráfico en sí.
- **En la capa 2 (Ethernet)** — Podemos filtrar protocolos que no tienen razón de ser en la infraestructura de un punto de intercambio de Internet, como DHCP y varios protocolos de descubrimiento específicos de proveedores (CDP, MNDP, etc.). LLDP está habilitado en todos los puertos. Como IX, buscamos habilitar únicamente los protocolos de capa 2 que dan soporte a la comunicación IP, es decir, protocolos de descubrimiento de vecinos como ARP e ICMPv6 Neighbor Discovery.

Ninguno de estos filtrados implica inspeccionar el contenido o la carga útil de tu tráfico. Somos una tubería, no un guardián.

### Sitio web

Podemos utilizar herramientas de análisis de uso como Google Analytics o PostHog para entender cómo usan este sitio web los visitantes. Estas herramientas pueden establecer cookies y recopilar datos de uso anonimizados, como las páginas visitadas, el tiempo en el sitio y la fuente de referencia. Los registros de acceso del servidor pueden conservarse durante un período limitado con fines operativos y de seguridad.

## Retención de datos

- **La información de contacto de los participantes** se conserva durante la vigencia de la conexión del participante al intercambio y durante un período razonable posterior con fines de facturación y legales.
- **Los contadores de interfaz** se conservan en nuestros sistemas de monitoreo y se eliminan progresivamente según las políticas de retención estándar (normalmente hasta dos años con granularidad decreciente).
- **Los datos de muestras de flujo** se conservan en forma agregada o resumida. Las muestras sin procesar no se conservan a largo plazo.

## Compartición de datos

No vendemos, alquilamos ni compartimos información personal u organizacional con terceros, excepto:

- Cuando lo exija la ley o un proceso legal válido.
- Con proveedores de servicios que ayudan a operar el intercambio (p. ej., facturación), sujetos a obligaciones de confidencialidad.
- Estadísticas de tráfico agregadas y anonimizadas que no puedan identificar a participantes individuales ni sus patrones de tráfico.

## Contacto

Las preguntas sobre esta política pueden dirigirse a [tech-c@sfmix.org](mailto:tech-c@sfmix.org).

*Última actualización: mayo de 2026*
