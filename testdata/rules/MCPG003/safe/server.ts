const apiKey = process.env.SEARCH_API_KEY;
const tokenizer = "cl100k_base";
export const headers = { Authorization: `Bearer ${apiKey}` };
