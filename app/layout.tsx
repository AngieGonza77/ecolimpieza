import type { Metadata, Viewport } from 'next'
import './globals.css'

export const metadata: Metadata = { title: 'Ecolimpieza | Gestión comercial', description: 'Panel de gestión para ventas, inventario, caja y clientes de Ecolimpieza', manifest: '/manifest.webmanifest' }
export const viewport: Viewport = { themeColor: '#073B91', width: 'device-width', initialScale: 1, maximumScale: 1, userScalable: false }
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="es"><body>{children}</body></html> }
