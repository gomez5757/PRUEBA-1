# Luna Engine

Servicio genérico de inferencia para el carril autónomo de Diana+.

- Ejecuta Codex CLI con GPT-5.6 Luna en Railway.
- No contiene código privado de Diana+.
- No contiene tokens GitHub ni credenciales de ChatGPT en el repositorio.
- La autenticación Codex vive únicamente en un volumen persistente privado de Railway.
- El acceso de Diana+ al motor se valida mediante GitHub Actions OIDC.
- El motor rechaza runners que no sean self-hosted y limita la concurrencia para proteger memoria.

Este repositorio público contiene únicamente infraestructura genérica.
