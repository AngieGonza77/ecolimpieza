# Plan de pruebas — ciclo de vida de sesiones

Estado: preparado; pendiente ejecutar en una base aislada.  
Proyecto objetivo: Ecolimpieza_app.  
Migraciones: `20261110_users_security.sql` + `20261117_session_lifecycle_security.sql`.

> No ejecutar en la base principal. La base principal no tiene migraciones aplicadas y debe permanecer intacta durante esta etapa.

## 1. Preparación del entorno

1. Crear una rama de desarrollo de Supabase o un proyecto temporal aislado.
2. Aplicar primero `20261110_users_security.sql`.
3. Aplicar después `20261117_session_lifecycle_security.sql`.
4. Confirmar que ambas migraciones aparecen en el historial y que no hubo errores.
5. Configurar el Custom Access Token Hook en Authentication > Hooks:
   - Función: `public.eco_custom_access_token_hook`
   - Evento: Custom Access Token
6. Verificar que el rol `supabase_auth_admin` puede ejecutar el hook y leer los datos mínimos requeridos.
7. Crear una jefa inicial y dos vendedoras de prueba. No reutilizar cuentas reales ni credenciales de producción.

## 2. Matriz de pruebas funcionales

| ID | Escenario | Acción | Resultado esperado |
|---|---|---|---|
| S01 | Vendedora activa | Iniciar sesión con contraseña | Login permitido; JWT contiene `session_id`. |
| S02 | Desactivar sin cerrar sesión | Jefa desactiva a la vendedora | Operación y auditoría exitosas; sesión que ya existía queda concedida. |
| S03 | Sesión existente | Consultar perfil y datos permitidos | Acceso continúa mientras la sesión siga en Auth. |
| S04 | Renovación existente | Esperar/forzar renovación del token | Hook permite `token_refresh` para el `session_id` concedido. |
| S05 | Nuevo login inactivo | Intentar login con contraseña | Hook rechaza la emisión del token. |
| S06 | Otra vía de autenticación | Intentar OTP/magic link/OAuth en cuenta inactiva | Hook rechaza métodos distintos de `token_refresh`. |
| S07 | Cierre de sesión | La vendedora ejecuta sign out | Supabase elimina la sesión; el grant deja de autorizar acceso. |
| S08 | Reingreso después del cierre | Intentar iniciar sesión otra vez | Rechazado mientras `activo=false`. |
| S09 | Sesión anterior tras sign out | Reutilizar access token anterior contra una operación RLS protegida | La autorización de cuenta inactiva falla al no existir la fila en `auth.sessions`. |
| S10 | Varias sesiones previas | Abrir dos dispositivos y desactivar | Ambas sesiones previas siguen autorizadas hasta cerrar cada sesión. |
| S11 | Reactivar | Jefa reactiva la vendedora | Se eliminan grants anteriores; cuenta activa puede iniciar sesión de nuevo. |
| S12 | Token antiguo tras reactivar | Usar una sesión que se había cerrado antes de reactivar | No se recupera la sesión cerrada; requiere login nuevo. |
| S13 | Usuario inactivo llama RPC admin | Intentar desactivar/editar otra cuenta | Rechazado; solo jefa activa autenticada puede administrar. |
| S14 | Usuario anónimo | Intentar llamar RPC administrativa | Rechazado. |
| S15 | Integridad de auditoría | Forzar fallo de inserción de auditoría en transacción de prueba | La operación administrativa completa hace rollback. |

## 3. Pruebas de concurrencia

- C01: login de vendedora y desactivación simultáneos; repetir suficientes veces. Nunca debe quedar autorizada una sesión cuyo inicio no terminó antes de la desactivación.
- C02: dos operaciones administrativas cruzadas; comprobar ausencia de deadlocks y consistencia de los locks.
- C03: refresh simultáneo con desactivación; refresh solo pasa si la sesión queda registrada como existente antes de desactivar.
- C04: logout simultáneo con refresh; el resultado debe respetar el estado real de la sesión en `auth.sessions`.

## 4. Pruebas de seguridad y regresión

- RLS activo en todas las tablas; ninguna tabla privada accesible directamente por `anon` o `authenticated`.
- `authenticated` solo puede ejecutar las RPC administrativas nuevas; las firmas antiguas con `actor uuid` ya no existen.
- `service_role` no tiene EXECUTE en las nuevas RPC administrativas.
- El hook solo es ejecutable por `supabase_auth_admin`.
- `private.eco_session_allowed()` solo es ejecutable por `authenticated` y vive en el esquema privado.
- La jefa activa conserva lectura administrativa de perfiles y auditoría.
- La vendedora activa conserva las operaciones ordinarias autorizadas.
- El perfil inactivo no puede editar su rol ni su estado.
- Revisar advisors de seguridad y rendimiento al final.

## 5. Criterios para aprobar

No pasar a producción hasta que:
- Todas las pruebas S01–S15 y C01–C04 pasen.
- No existan grants inesperados en funciones o tablas.
- El hook esté habilitado y se haya probado en el proyecto aislado.
- Las policies y funciones coincidan con el diseño revisado.
- Se documente el comportamiento real de sign out, refresh y expiración del JWT.

## 6. Notas importantes

- El access token JWT no se invalida por sí solo al cerrar sesión; por eso las operaciones sensibles de una cuenta inactiva comprueban también que la sesión siga existiendo en `auth.sessions`.
- El hook controla la emisión/renovación de JWT; RLS controla el acceso a datos con el token actual.
- No confundir una prueba exitosa de la función SQL con una prueba exitosa del flujo completo de Supabase Auth.
