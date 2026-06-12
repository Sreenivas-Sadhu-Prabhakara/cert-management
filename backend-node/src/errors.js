export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const notFound = (message = 'no such key') =>
  new ApiError(404, 'NOT_FOUND', message);
export const invalidState = (message) =>
  new ApiError(409, 'INVALID_STATE', message);
export const invalidRequest = (message) =>
  new ApiError(400, 'INVALID_REQUEST', message);
export const unauthorized = (message = 'authentication failed') =>
  new ApiError(401, 'UNAUTHORIZED', message);
