import type { NextAuthConfig } from 'next-auth';
import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { sql } from '@vercel/postgres';
import { z } from 'zod';
import { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
import { getUser } from './lib/data';

export const auth = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const { email, password } = credentials;
        const user = await getUser(email);
        if (!user) return null;
        const passwordsMatch = await bcrypt.compare(password, user.password);

        if (passwordsMatch) return user;

        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});

// Optionally, you can export signIn and signOut if needed
export const { signIn, signOut } = auth;
