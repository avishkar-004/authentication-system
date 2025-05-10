import React, { createContext, useContext, useReducer, useEffect, useState } from 'react';

// ========================================
// AUTHENTICATION CONTEXT & STATE MANAGEMENT
// ========================================

const AuthContext = createContext();

const authReducer = (state, action) => {
  switch (action.type) {
    case 'LOGIN_START':
      return { ...state, loading: true, error: null };
    case 'LOGIN_SUCCESS':
      return {
        ...state,
        loading: false,
        isAuthenticated: true,
        user: action.payload.user,
        token: action.payload.accessToken,
        error: null
      };
    case 'LOGIN_FAILURE':
      return {
        ...state,
        loading: false,
        isAuthenticated: false,
        user: null,
        token: null,
        error: action.payload
      };
    case 'LOGOUT':
      return {
        ...state,
        isAuthenticated: false,
        user: null,
        token: null,
        error: null,
        loading: false
      };
    case 'SET_ERROR':
      return { ...state, error: action.payload, loading: false };
    case 'CLEAR_ERROR':
      return { ...state, error: null };
    default:
      return state;
  }
};

// ========================================
// API SERVICE CLASS
// ========================================

class AuthAPI {
  constructor() {
    this.baseURL = 'http://localhost:5000/api';
    this.refreshPromise = null;
  }

  async request(endpoint, options = {}) {
    const url = `${this.baseURL}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
      credentials: 'include',
      ...options,
    };

    // Add auth header if token exists
    const token = localStorage.getItem('accessToken');
    if (token && !options.skipAuth) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      // Handle token expiration
      if (response.status === 401 && data.message === 'Token expired' && !options.skipRefresh) {
        const refreshed = await this.refreshToken();
        if (refreshed) {
          return this.request(endpoint, { ...options, skipRefresh: true });
        } else {
          this.handleLogout();
          throw new Error('Session expired. Please login again.');
        }
      }

      if (!response.ok) {
        throw new Error(data.message || `HTTP error! status: ${response.status}`);
      }

      return data;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }

  async refreshToken() {
    if (this.refreshPromise) return this.refreshPromise;

    this.refreshPromise = (async () => {
      try {
        const response = await fetch(`${this.baseURL}/auth/refresh`, {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' }
        });

        if (response.ok) {
          const data = await response.json();
          localStorage.setItem('accessToken', data.data.accessToken);
          localStorage.setItem('user', JSON.stringify(data.data.user));
          return true;
        }
        return false;
      } catch (error) {
        console.error('Token refresh failed:', error);
        return false;
      } finally {
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  handleLogout() {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('user');
  }

  async login(credentials) {
    const data = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
      skipAuth: true
    });

    if (data.success) {
      localStorage.setItem('accessToken', data.data.accessToken);
      localStorage.setItem('user', JSON.stringify(data.data.user));
    }

    return data;
  }

  async register(userData) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
      skipAuth: true
    });
  }

  async verifyOTP(otpData) {
    return this.request('/auth/verify-otp', {
      method: 'POST',
      body: JSON.stringify(otpData),
      skipAuth: true
    });
  }

  async sendPasswordResetOTP(data) {
    return this.request('/auth/send-password-reset-otp', {
      method: 'POST',
      body: JSON.stringify(data),
      skipAuth: true
    });
  }

  async resetPassword(data) {
    return this.request('/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify(data),
      skipAuth: true
    });
  }

  async logout() {
    try {
      await this.request('/auth/logout', { method: 'POST' });
    } catch (error) {
      console.error('Logout API call failed:', error);
    }
    this.handleLogout();
  }
}

const authAPI = new AuthAPI();

// ========================================
// AUTH PROVIDER
// ========================================

export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, {
    isAuthenticated: false,
    user: null,
    token: null,
    loading: true,
    error: null
  });

  useEffect(() => {
    const initAuth = () => {
      try {
        const token = localStorage.getItem('accessToken');
        const user = localStorage.getItem('user');

        if (token && user) {
          dispatch({
            type: 'LOGIN_SUCCESS',
            payload: {
              accessToken: token,
              user: JSON.parse(user)
            }
          });
        } else {
          dispatch({ type: 'LOGOUT' });
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
        dispatch({ type: 'LOGOUT' });
      }
    };

    initAuth();
  }, []);

  const login = async (credentials) => {
    dispatch({ type: 'LOGIN_START' });
    try {
      const response = await authAPI.login(credentials);
      if (response.success) {
        dispatch({ type: 'LOGIN_SUCCESS', payload: response.data });
        return { success: true, data: response.data };
      } else {
        dispatch({ type: 'LOGIN_FAILURE', payload: response.message });
        return { success: false, message: response.message };
      }
    } catch (error) {
      const message = error.message || 'Login failed';
      dispatch({ type: 'LOGIN_FAILURE', payload: message });
      return { success: false, message };
    }
  };

  const register = async (userData) => {
    try {
      return await authAPI.register(userData);
    } catch (error) {
      return { success: false, message: error.message };
    }
  };

  const verifyOTP = async (otpData) => {
    try {
      return await authAPI.verifyOTP(otpData);
    } catch (error) {
      return { success: false, message: error.message };
    }
  };

  const sendPasswordResetOTP = async (data) => {
    try {
      return await authAPI.sendPasswordResetOTP(data);
    } catch (error) {
      return { success: false, message: error.message };
    }
  };

  const resetPassword = async (data) => {
    try {
      return await authAPI.resetPassword(data);
    } catch (error) {
      return { success: false, message: error.message };
    }
  };

  const logout = async () => {
    await authAPI.logout();
    dispatch({ type: 'LOGOUT' });
  };

  const clearError = () => dispatch({ type: 'CLEAR_ERROR' });

  const value = {
    ...state,
    login,
    register,
    verifyOTP,
    sendPasswordResetOTP,
    resetPassword,
    logout,
    clearError
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// ========================================
// REUSABLE COMPONENTS
// ========================================

// Toast Component
export const Toast = ({ message, type = 'success', onClose, duration = 4000 }) => {
  useEffect(() => {
    if (message) {
      const timer = setTimeout(onClose, duration);
      return () => clearTimeout(timer);
    }
  }, [message, duration, onClose]);

  if (!message) return null;

  const bgColor = type === 'success' ? 'bg-green-500' : 'bg-red-500';
  const icon = type === 'success' ? '✓' : '✕';

  return (
    <div className={`fixed top-5 left-1/2 transform -translate-x-1/2 z-50 ${bgColor} text-white px-6 py-3 rounded-lg shadow-lg flex items-center space-x-3 transition-all duration-300 ease-out`}>
      <span className="text-lg font-bold">{icon}</span>
      <span className="font-semibold">{message}</span>
      <button 
        onClick={onClose}
        className="ml-2 text-white hover:text-gray-200 transition-colors"
      >
        ×
      </button>
    </div>
  );
};

// Loading Spinner
export const LoadingSpinner = ({ size = 'md', className = '' }) => {
  const sizes = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8'
  };

  return (
    <div className={`${sizes[size]} ${className} animate-spin rounded-full border-2 border-gray-300 border-t-blue-600`} />
  );
};

// Enhanced Button
export const Button = ({ 
  children, 
  onClick, 
  type = 'button', 
  variant = 'primary', 
  size = 'md', 
  loading = false, 
  disabled = false,
  className = '',
  ...props 
}) => {
  const baseClasses = 'font-semibold rounded-xl transition-all duration-300 transform hover:scale-105 active:scale-95 flex items-center justify-center space-x-2 focus:outline-none focus:ring-2 focus:ring-offset-2';
  
  const variants = {
    primary: 'bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 text-white shadow-lg hover:shadow-xl focus:ring-blue-500',
    secondary: 'border-2 border-blue-500 text-blue-600 hover:bg-blue-50 focus:ring-blue-500',
    success: 'bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 text-white shadow-lg hover:shadow-xl focus:ring-green-500',
    danger: 'bg-gradient-to-r from-red-600 to-red-700 hover:from-red-700 hover:to-red-800 text-white shadow-lg hover:shadow-xl focus:ring-red-500'
  };

  const sizes = {
    sm: 'px-4 py-2 text-sm',
    md: 'px-6 py-3 text-base',
    lg: 'px-8 py-4 text-lg'
  };

  const isDisabled = disabled || loading;

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={isDisabled}
      className={`${baseClasses} ${variants[variant]} ${sizes[size]} ${className} ${isDisabled ? 'opacity-50 cursor-not-allowed' : ''}`}
      {...props}
    >
      {loading && <LoadingSpinner size="sm" />}
      <span>{children}</span>
    </button>
  );
};

// Form Input Component
export const FormInput = ({ 
  label, 
  type = 'text', 
  value, 
  onChange, 
  error, 
  placeholder,
  required = false,
  disabled = false,
  ...props 
}) => {
  return (
    <div className="space-y-2">
      {label && (
        <label className="text-sm font-semibold text-gray-700">
          {label} {required && <span className="text-red-500">*</span>}
        </label>
      )}
      <input
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        disabled={disabled}
        className={`w-full px-4 py-3 rounded-xl border-2 transition-all duration-300 focus:outline-none focus:ring-0 ${
          error
            ? 'border-red-300 focus:border-red-500 bg-red-50'
            : 'border-gray-200 focus:border-blue-500 bg-white hover:border-blue-300'
        } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
        {...props}
      />
      {error && (
        <p className="text-red-500 text-sm mt-1">{error}</p>
      )}
    </div>
  );
};

// ========================================
// UNIFIED LOGIN COMPONENT
// ========================================

const UnifiedLogin = () => {
  const { login, loading, error, clearError } = useAuth();
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    role: 'buyer'
  });
  const [formMode, setFormMode] = useState('login'); // 'login', 'sendOtp', 'resetPassword'
  const [otpData, setOtpData] = useState({
    email: '',
    otp: '',
    newPassword: '',
    confirmPassword: '',
    role: ''
  });
  const [toast, setToast] = useState({ show: false, message: '', type: '' });

  const showToast = (message, type = 'success') => {
    setToast({ show: true, message, type });
  };

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (error) clearError();
  };

  const handleOtpInputChange = (field, value) => {
    setOtpData(prev => ({ ...prev, [field]: value }));
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    
    if (!formData.email || !formData.password) {
      showToast('Please fill in all fields', 'error');
      return;
    }

    const result = await login(formData);
    
    if (result.success) {
      showToast('Login successful! Welcome back!', 'success');
      setTimeout(() => {
        // In a real app, this would navigate to dashboard
        console.log('Redirecting to dashboard...', result.data.user.role);
      }, 1500);
    } else {
      showToast(result.message || 'Login failed', 'error');
    }
  };

  const handleSendOtp = async (e) => {
    e.preventDefault();
    
    if (!formData.email) {
      showToast('Please enter your email address', 'error');
      return;
    }

    try {
      const { sendPasswordResetOTP } = useAuth();
      const result = await sendPasswordResetOTP({
        email: formData.email,
        role: formData.role
      });

      if (result.success) {
        setOtpData(prev => ({ ...prev, email: formData.email, role: formData.role }));
        setFormMode('resetPassword');
        showToast('OTP sent to your email!', 'success');
      } else {
        showToast(result.message || 'Failed to send OTP', 'error');
      }
    } catch (error) {
      showToast('Network error. Please try again.', 'error');
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();

    if (!otpData.otp || !otpData.newPassword || !otpData.confirmPassword) {
      showToast('Please fill in all fields', 'error');
      return;
    }

    if (otpData.newPassword !== otpData.confirmPassword) {
      showToast('Passwords do not match', 'error');
      return;
    }

    if (otpData.newPassword.length < 8) {
      showToast('Password must be at least 8 characters', 'error');
      return;
    }

    try {
      const { resetPassword } = useAuth();
      const result = await resetPassword({
        email: otpData.email,
        otp: otpData.otp,
        new_password: otpData.newPassword,
        role: otpData.role
      });

      if (result.success) {
        showToast('Password reset successful! You can now log in.', 'success');
        setFormMode('login');
        setOtpData({ email: '', otp: '', newPassword: '', confirmPassword: '', role: '' });
      } else {
        showToast(result.message || 'Password reset failed', 'error');
      }
    } catch (error) {
      showToast('Network error. Please try again.', 'error');
    }
  };

  const renderLoginForm = () => (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-purple-600">
            Welcome to FreshMarket
          </span>
        </h1>
        <p className="text-gray-600">Sign in to your account</p>
      </div>

      <div onSubmit={handleLogin}>
        <div className="space-y-4">
          <FormInput
            label="Email"
            type="email"
            value={formData.email}
            onChange={(e) => handleInputChange('email', e.target.value)}
            placeholder="Enter your email"
            required
          />

          <FormInput
            label="Password"
            type="password"
            value={formData.password}
            onChange={(e) => handleInputChange('password', e.target.value)}
            placeholder="Enter your password"
            required
          />

          <div className="space-y-2">
            <label className="text-sm font-semibold text-gray-700">Role *</label>
            <select
              value={formData.role}
              onChange={(e) => handleInputChange('role', e.target.value)}
              className="w-full px-4 py-3 rounded-xl border-2 border-gray-200 focus:border-blue-500 bg-white hover:border-blue-300 transition-all duration-300 focus:outline-none focus:ring-0"
            >
              <option value="buyer">Buyer</option>
              <option value="seller">Seller</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          <div className="flex justify-end">
            <button
              type="button"
              onClick={() => setFormMode('sendOtp')}
              className="text-blue-600 hover:text-blue-800 font-medium transition-colors"
            >
              Forgot Password?
            </button>
          </div>

          <Button
            type="button"
            variant="primary"
            size="lg"
            loading={loading}
            disabled={loading}
            className="w-full"
            onClick={handleLogin}
          >
            {loading ? 'Signing In...' : 'Sign In'}
          </Button>
        </div>
      </div>
    </div>
  );

  const renderSendOtpForm = () => (
    <div className="space-y-6">
      <button
        type="button"
        onClick={() => setFormMode('login')}
        className="flex items-center text-gray-600 hover:text-gray-800 transition-colors mb-6"
      >
        ← Back to Login
      </button>

      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Forgot Password?</h2>
        <p className="text-gray-600">Enter your email to receive a reset code</p>
      </div>

      <div className="space-y-4">
        <FormInput
          label="Email"
          type="email"
          value={formData.email}
          onChange={(e) => handleInputChange('email', e.target.value)}
          placeholder="Enter your email"
          required
        />

        <Button
          type="button"
          variant="primary"
          size="lg"
          className="w-full"
          onClick={handleSendOtp}
        >
          Send Reset Code
        </Button>
      </div>
    </div>
  );

  const renderResetPasswordForm = () => (
    <div className="space-y-6">
      <button
        type="button"
        onClick={() => setFormMode('sendOtp')}
        className="flex items-center text-gray-600 hover:text-gray-800 transition-colors mb-6"
      >
        ← Back
      </button>

      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">Reset Password</h2>
        <p className="text-gray-600">Enter the code and your new password</p>
      </div>

      <div className="space-y-4">
        <FormInput
          label="Verification Code"
          type="text"
          value={otpData.otp}
          onChange={(e) => handleOtpInputChange('otp', e.target.value.replace(/\D/g, '').slice(0, 6))}
          placeholder="Enter 6-digit code"
          maxLength="6"
          required
        />

        <FormInput
          label="New Password"
          type="password"
          value={otpData.newPassword}
          onChange={(e) => handleOtpInputChange('newPassword', e.target.value)}
          placeholder="Enter new password"
          required
        />

        <FormInput
          label="Confirm Password"
          type="password"
          value={otpData.confirmPassword}
          onChange={(e) => handleOtpInputChange('confirmPassword', e.target.value)}
          placeholder="Confirm new password"
          required
        />

        <Button
          type="button"
          variant="success"
          size="lg"
          className="w-full"
          onClick={handleResetPassword}
        >
          Reset Password
        </Button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <Toast 
        message={toast.show ? toast.message : ''}
        type={toast.type}
        onClose={() => setToast({ show: false, message: '', type: '' })}
      />
      
      <div className="bg-white rounded-3xl shadow-xl p-8 w-full max-w-md">
        {formMode === 'login' && renderLoginForm()}
        {formMode === 'sendOtp' && renderSendOtpForm()}
        {formMode === 'resetPassword' && renderResetPasswordForm()}

        {error && (
          <div className="mt-4 bg-red-50 border border-red-200 rounded-lg p-3">
            <p className="text-red-600 text-sm">{error}</p>
          </div>
        )}
      </div>
    </div>
  );
};

// ========================================
// MAIN DEMO COMPONENT
// ========================================

const AuthDemo = () => {
  return (
    <AuthProvider>
      <UnifiedLogin />
    </AuthProvider>
  );
};

export default AuthDemo;