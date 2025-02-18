export interface ApiResponse<T> {
  success: boolean;
  message?: string;
  response?: T;
  time?: string;
  httpStatus?: string;
  isSuccess?: boolean;
}
