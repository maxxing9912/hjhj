// app/api/activate_premium/route.ts

import { NextResponse } from 'next/server';

export async function POST(req: Request) {
  // logica premium
  const success = true;

  if (success) {
    return NextResponse.json({ success: true });
  } else {
    return NextResponse.json({ success: false, message: 'Errore attivazione' }, { status: 400 });
  }
}