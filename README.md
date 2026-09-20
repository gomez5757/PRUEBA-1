# Luna Fabric — infraestructura pública

Infraestructura genérica para ejecutar workers Codex efímeros sin publicar el código privado de Diana+.

- **Inferencia:** GitHub-hosted runners efímeros ejecutan exclusivamente `gpt-5.6-luna` con razonamiento `max`.
- **Sin Codex Cloud:** este circuito no usa `@codex`, Work ni un agente principal Astra/Sol/Terra.
- **Railway no ejecuta modelos:** `luna-engine` actúa como broker/caja fuerte de autenticación y cola privada.
- **Credenciales:** la sesión ChatGPT/Codex permanece en un volumen privado de Railway; cada runner recibe solo una copia temporal cifrada y la destruye al terminar.
- **Código privado:** Diana+ no se guarda en este repositorio. Los snapshots y parches viajan temporalmente a través del broker autenticado con OIDC.
- **Sandbox:** los workers usan `workspace-write`, red local deshabilitada, búsqueda web deshabilitada, apps/conectores deshabilitados y AppArmor + bubblewrap en Ubuntu 24.04.
- **Fail closed:** si el modelo observado no es exactamente Luna, el esfuerzo no es `max`, falla la autenticación, el sandbox o la validación de rutas, el parche se rechaza.
- **Concurrencia:** la matrix dinámica puede usar varias VMs separadas; Railway no limita la RAM de los modelos.
- **Sin producción:** esta infraestructura no publica CWS, no modifica `main`, no despliega servicios de Diana+ ni accede a datos/licencias reales.

El coordinador en ChatGPT Web decide cuántos trabajos independientes merece la pena lanzar. GitHub privado sigue siendo la memoria y la fuente de verdad del producto.
