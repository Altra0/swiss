import { NextRequest, NextResponse } from 'next/server';
import { hash } from 'bcryptjs';
import prisma from '@/lib/prisma';
import { successResponse, errorResponse } from '@/lib/api-response';

export async function POST(req: NextRequest) {
  try {
    const { email, password, name } = await req.json();

    // Validate input
    if (!email || !password) {
      return NextResponse.json(
        errorResponse('Email and password are required'),
        { status: 400 }
      );
    }

    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return NextResponse.json(
        errorResponse('User already exists'),
        { status: 400 }
      );
    }

    // Hash password
    const hashedPassword = await hash(password, 12);

    // Create user
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    return NextResponse.json(successResponse(user), { status: 201 });
  } catch (error) {
    console.error('Registration error:', error);
    return NextResponse.json(
      errorResponse('Internal server error'),
      { status: 500 }
    );
  }
}
