import NextAuth from "next-auth";
import { JWT } from "next-auth/jwt";
import AzureADProvider from "next-auth/providers/azure-ad";
import { custom } from "openid-client";

custom.setHttpOptionsDefaults({
  timeout: 10000,
});

async function refreshAccessToken(token: JWT) {
  try {
    const url = `https://login.microsoftonline.com/${process.env.AZURE_AD_TENANT_ID}/oauth2/v2.0/token`;

    const body = new URLSearchParams({
      client_id: process.env.AZURE_AD_CLIENT_ID || "azure-ad-client-id",
      client_secret:
        process.env.AZURE_AD_CLIENT_SECRET || "azure-ad-client-secret",
      scope: "email openid profile User.Read offline_access",
      grant_type: "refresh_token",
      refresh_token: token.refreshToken as string,
    });

    const response = await fetch(url, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      method: "POST",
      body,
    });

    const refreshedTokens = await response.json();

    if (!response.ok) {
      throw refreshedTokens;
    }

    return {
      ...token,
      accessToken: refreshedTokens.access_token,
      accessTokenExpires: Date.now() + refreshedTokens.expires_in * 1000,
      refreshToken: refreshedTokens.refresh_token ?? token.refreshToken,
    };
  } catch (error) {
    return {
      ...token,
      error: "RefreshAccessTokenError",
    };
  }
}

export default NextAuth({
  providers: [
    AzureADProvider({
      clientId: process.env.AZURE_AD_CLIENT_ID || "azure-ad-client-id",
      clientSecret:
        process.env.AZURE_AD_CLIENT_SECRET || "azure-ad-client-secret",
      tenantId: process.env.AZURE_AD_TENANT_ID || "azure-ad-tenant-id",
      authorization: {
        params: { scope: "email openid profile offline_access" },
        
      }
    }),
  ],
  session: {
    strategy: "jwt",
  },
  secret: process.env.JWT_SECRET || "jwt-secret",
  callbacks: {
    async jwt({ token, user, account,profile }) {
      if (account && user) {
        return {
          accessToken: account.id_token,
          accessTokenExpires: account?.expires_at
            ? account.expires_at * 1000
            : 0,
          refreshToken: account.refresh_token,
          user,
        };
      }

      if (
        Date.now() <
          (token as JWT & { accessTokenExpires: number }).accessTokenExpires ||
        0
      ) {
        return token;
      }

      return refreshAccessToken(token);
    },
    async session({ session, token }: any) {
      if (session) {
        const profileImageUrl = `https://graph.microsoft.com/v1.0/me/photo/$value`;
        const response = await fetch(profileImageUrl, {
          headers: {
            Authorization: `Bearer ${token.accessToken}`,
          },
        });
        const profileData = await response.json();
        session.user = token.user;
        session.error = token.error;
        session.user.access_token_expires_at = token.accessTokenExpires;
        session.expires = token.accessTokenExpires;
        if(response.ok) {
          session.user.profile_image = profileData;
        }
        
      }
      return session;
    },
  },
});
