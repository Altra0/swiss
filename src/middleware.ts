import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { verify } from 'jsonwebtoken';

// Paths that don't require authentication
const publicPaths = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/forgot-password',
];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public paths
  if (publicPaths.includes(pathname)) {
    return NextResponse.next();
  }

  // Check for protected API routes
  if (pathname.startsWith('/api/')) {
    const token = request.cookies.get('token')?.value;

    if (!token) {
      return NextResponse.json(
        { success: false, error: 'Authentication required' },
        { status: 401 }
      );
    }

    try {
      // Verify JWT
      const decoded = verify(
        token,
        process.env.JWT_SECRET || 'your-secret-key'
      );

      // Add user info to headers for route handlers
      const requestHeaders = new Headers(request.headers);
      requestHeaders.set('x-user-id', (decoded as any).userId);
      requestHeaders.set('x-user-role', (decoded as any).role);

      return NextResponse.next({
        headers: requestHeaders,
      });
    } catch (error) {
      return NextResponse.json(
        { success: false, error: 'Invalid token' },
        { status: 401 }
      );
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/api/:path*',
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
