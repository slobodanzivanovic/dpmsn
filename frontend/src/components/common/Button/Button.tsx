import React, { ButtonHTMLAttributes } from "react";
import "./button.scss";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  isLoading?: boolean;
  variant?: "primary" | "secondary" | "outline";
  fullWidth?: boolean;
}

const Button: React.FC<ButtonProps> = ({
  children,
  className = "",
  isLoading = false,
  variant = "primary",
  fullWidth = false,
  disabled,
  ...rest
}) => {
  return (
    <button
      className={`
        button
        button-${variant}
        ${isLoading ? "loading" : ""}
        ${fullWidth ? "full-width" : ""}
        ${className}
      `}
      disabled={disabled || isLoading}
      {...rest}
    >
      <span className="button-content">{children}</span>
      {isLoading && <span className="loading-spinner" />}
    </button>
  );
};

export default Button;
