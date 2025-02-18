import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  const tokensStr = request.cookies.get("tokens")?.value;
  const isAuthenticated = !!tokensStr;

  let isTokenExpired = false;
  if (tokensStr) {
    try {
      const tokens = JSON.parse(tokensStr);
      const now = Math.floor(Date.now() / 1000);
      isTokenExpired = tokens.accessTokenExpiresAt < now;
    } catch (e) {
      isTokenExpired = true;
    }
  }

  const isAuthPage =
    request.nextUrl.pathname.startsWith("/login") ||
    request.nextUrl.pathname.startsWith("/register");

  const isPublicRoute =
    request.nextUrl.pathname === "/" ||
    request.nextUrl.pathname.startsWith("/about") ||
    request.nextUrl.pathname.startsWith("/contact");

  if ((!isAuthenticated || isTokenExpired) && !isAuthPage && !isPublicRoute) {
    const redirectUrl = new URL("/login", request.url);
    redirectUrl.searchParams.set("redirect", request.nextUrl.pathname);
    return NextResponse.redirect(redirectUrl);
  }

  if (isAuthenticated && !isTokenExpired && isAuthPage) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"],
};
