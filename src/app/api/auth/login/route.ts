import { NextRequest, NextResponse } from 'next/server';
import { compare } from 'bcryptjs';
import { sign } from 'jsonwebtoken';
import prisma from '@/lib/prisma';
import { successResponse, errorResponse } from '@/lib/api-response';

export async function POST(req: NextRequest) {
  try {
    const { email, password } = await req.json();

    // Validate input
    if (!email || !password) {
      return NextResponse.json(
        errorResponse('Email and password are required'),
        { status: 400 }
      );
    }

    // Find user
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return NextResponse.json(
        errorResponse('Invalid credentials'),
        { status: 401 }
      );
    }

    // Verify password
    const isValid = await compare(password, user.password);

    if (!isValid) {
      return NextResponse.json(
        errorResponse('Invalid credentials'),
        { status: 401 }
      );
    }

    // Generate JWT
    const token = sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '1d' }
    );

    const response = NextResponse.json(
      successResponse({ token }),
      { status: 200 }
    );

    // Set HTTP-only cookie
    response.cookies.set('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 86400, // 1 day
      path: '/',
    });

    return response;
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      errorResponse('Internal server error'),
      { status: 500 }
    );
  }
}
