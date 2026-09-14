declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
      };

      session?: {
        id: string;
        userId: string;
        tokenHash: string;
        expiresAt: string | Date;
      };
    }
  }
}

export {};