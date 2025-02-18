import { LoginCredentials } from "@/types/LoginCredentials";
import { RegisterCredentials } from "@/types/RegisterCredentials";
import { ApiResponse } from "@/types/ApiResponse";
import { AuthTokens } from "@/types/AuthTokens"; // API Endpoints

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:1110";
const AUTH_ENDPOINTS = {
  LOGIN: "/api/authentication/users/login",
  REGISTER: "/api/authentication/users/register",
  LOGOUT: "/api/authentication/users/logout",
  REFRESH_TOKEN: "/api/authentication/users/refresh-token",
  VALIDATE_TOKEN: "/api/authentication/users/validate-token",
};

class AuthError extends Error {
  status?: number;

  constructor(message: string, status?: number) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

export async function login(credentials: LoginCredentials): Promise<void> {
  try {
    const response = await fetch(`${API_BASE_URL}${AUTH_ENDPOINTS.LOGIN}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(credentials),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new AuthError(errorData.message || "Login failed", response.status);
    }

    const data: ApiResponse<AuthTokens> = await response.json();
    if (!data.isSuccess || !data.response) {
      throw new AuthError(data.message || "Login failed");
    }

    document.cookie = `tokens=${JSON.stringify(data.response)}; path=/; max-age=${getMaxAge(data.response.accessTokenExpiresAt)}; SameSite=Strict`;
    localStorage.setItem("tokens", JSON.stringify(data.response));
  } catch (error) {
    if (error instanceof AuthError) {
      throw error;
    }
    throw new AuthError("Network error. Please try again later.");
  }
}

export async function register(
  credentials: RegisterCredentials,
): Promise<void> {
  try {
    const response = await fetch(`${API_BASE_URL}${AUTH_ENDPOINTS.REGISTER}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(credentials),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new AuthError(
        errorData.message || "Registration failed",
        response.status,
      );
    }

    const data: ApiResponse<void> = await response.json();
    if (!data.isSuccess) {
      throw new AuthError(data.message || "Registration failed");
    }
  } catch (error) {
    if (error instanceof AuthError) {
      throw error;
    }
    throw new AuthError("Network error. Please try again later.");
  }
}

export async function logout(): Promise<void> {
  try {
    const tokens = getTokens();
    if (!tokens) {
      clearAuthData();
      return;
    }

    const response = await fetch(`${API_BASE_URL}${AUTH_ENDPOINTS.LOGOUT}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokens.accessToken}`,
      },
      body: JSON.stringify({
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      }),
    });

    clearAuthData();
    if (!response.ok) {
      const errorData = await response.json();
      console.error("Logout error:", errorData);
    }
  } catch (error) {
    console.error("Logout error:", error);
    clearAuthData();
  }
}

export async function refreshToken(): Promise<AuthTokens | null> {
  const tokens = getTokens();
  if (!tokens?.refreshToken) return null;

  try {
    const response = await fetch(
      `${API_BASE_URL}${AUTH_ENDPOINTS.REFRESH_TOKEN}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ refreshToken: tokens.refreshToken }),
      },
    );

    if (!response.ok) {
      clearAuthData();
      return null;
    }

    const data: ApiResponse<AuthTokens> = await response.json();
    if (!data.isSuccess || !data.response) {
      clearAuthData();
      return null;
    }

    document.cookie = `tokens=${JSON.stringify(data.response)}; path=/; max-age=${getMaxAge(data.response.accessTokenExpiresAt)}; SameSite=Strict`;
    localStorage.setItem("tokens", JSON.stringify(data.response));
    return data.response;
  } catch (error) {
    console.error("Token refresh error:", error);
    clearAuthData();
    return null;
  }
}

export function getTokens(): AuthTokens | null {
  if (typeof window !== "undefined") {
    const tokensStr = localStorage.getItem("tokens");
    if (tokensStr) {
      try {
        return JSON.parse(tokensStr);
      } catch (e) {
        return null;
      }
    }
  }
  const cookies = parseCookies();
  const tokensCookie = cookies["tokens"];
  if (tokensCookie) {
    try {
      return JSON.parse(tokensCookie);
    } catch (e) {
      return null;
    }
  }
  return null;
}

export function isAuthenticated(): boolean {
  const tokens = getTokens();
  if (!tokens) return false;
  const now = Math.floor(Date.now() / 1000);
  if (tokens.accessTokenExpiresAt && tokens.accessTokenExpiresAt < now) {
    refreshToken();
    return false;
  }
  return true;
}

function clearAuthData(): void {
  if (typeof window !== "undefined") {
    localStorage.removeItem("tokens");
  }
  document.cookie = "tokens=; path=/; max-age=0; SameSite=Strict";
}

function parseCookies(): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (typeof document === "undefined") return cookies;
  document.cookie.split(";").forEach(cookie => {
    const parts = cookie.split("=");
    const name = parts[0]?.trim();
    if (name) cookies[name] = parts[1] || "";
  });
  return cookies;
}

function getMaxAge(expiresAt: number): number {
  const now = Math.floor(Date.now() / 1000);
  return Math.max(0, expiresAt - now);
}
