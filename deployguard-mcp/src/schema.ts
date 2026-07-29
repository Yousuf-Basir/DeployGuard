import { z } from "zod";

export const statusEnum = z.enum(["ok", "warn", "fail"]);

// Base fields every tool's outputSchema extends with its own specifics.
export const checkResultShape = {
  status: statusEnum,
  summary: z.string(), // one-line human-readable summary, same text used in `content`
};
