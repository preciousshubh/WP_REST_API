# New REST API Plugin

This plugin provides various REST API routes for user management and other functionalities in WordPress. It allows users to register, update their profiles, manage password reset functionality, create posts, manage products, and more.

## Plugin Details

- **Plugin Name**: New REST API Plugin
- **Version**: 1.0.0
- **Author**: DP
- **Author URI**: [https://www.examplepluginauthor.com](https://www.examplepluginauthor.com/)
- **Plugin URI**: [https://www.exampleplugin.com/plugin](https://www.exampleplugin.com/plugin)
- **Description**: A WordPress plugin that provides REST API routes for managing user-related functionalities such as registration, profile updates, password reset, image uploads, posts creation, and product management.

## Features

- **User Registration**: Allows new users to register with validation for username, email, and password.
- **Profile Management**: Enables users to update their profiles, including first name, last name, email, company details, and location.
- **JWT Authentication**: Supports JWT-based user authentication for secure API access.
- **Password Reset**: Allows users to reset their passwords through OTP verification.
- **Profile Image Upload**: Users can upload their profile images via both base64 encoding or file upload.
- **Create and Manage Posts**: Users can create, update, and view posts using the API.
- **Product Management**: Allows creating and managing WooCommerce products, including variations.
- **Custom Error Handling**: Provides custom error and success responses for better clarity in API interactions.

## Installation

1. Clone this repository to your WordPress `wp-content/plugins` directory or download it as a ZIP file and extract it there.
2. In the WordPress admin dashboard, go to **Plugins > Installed Plugins** and activate the "New REST API Plugin".
3. Your REST API routes will now be accessible at `http://yourdomain.com/wp-json/api/v1/`.

## API Endpoints

### 1. **User Registration**
- **URL**: `/api/v1/register`
- **Method**: `POST`
- **Parameters**:
  - `username` (string) - Required.
  - `email` (string) - Required.
  - `password` (string) - Required.
  - `confirmpassword` (string) - Required.
  - `first_name` (string) - Required.
  - `last_name` (string) - Required.
  - `company_id` (string) - Optional.
  - `location_name` (string) - Optional.
- **Response**: On success, returns user details. On failure, returns appropriate error message.

### 2. **Get User Profile**
- **URL**: `/api/v1/getUser`
- **Method**: `POST`
- **Response**: Returns user profile details such as `username`, `email`, `full_name`, etc.

### 3. **Forget Password**
- **URL**: `/api/v1/forgetPassword`
- **Method**: `POST`
- **Parameters**:
  - `email` (string) - Required.
- **Response**: Sends an OTP for password reset if email is registered.

### 4. **Verify OTP for Password Reset**
- **URL**: `/api/v1/verifyOTP`
- **Method**: `POST`
- **Parameters**:
  - `email` (string) - Required.
  - `otp` (string) - Required.
- **Response**: Confirms OTP verification and allows password reset.

### 5. **Reset Password**
- **URL**: `/api/v1/resetPassword`
- **Method**: `POST`
- **Parameters**:
  - `email` (string) - Required.
  - `new_password` (string) - Required.
- **Response**: Confirms that the password has been successfully changed.

### 6. **Update Profile**
- **URL**: `/api/v1/updateProfile`
- **Method**: `POST`
- **Parameters**:
  - `email` (string) - Required.
  - `first_name` (string) - Required.
  - `last_name` (string) - Required.
  - `company_id` (string) - Optional.
  - `location_name` (string) - Optional.
  - `profile_image` (file) - Optional.
- **Response**: Updates the user profile and returns the updated data.

### 7. **Update Profile with Base64 Image**
- **URL**: `/api/v1/updateProfile2`
- **Method**: `POST`
- **Parameters**:
  - `email` (string) - Required.
  - `first_name` (string) - Required.
  - `last_name` (string) - Required.
  - `company_id` (string) - Optional.
  - `location_name` (string) - Optional.
  - `profile_image_base64` (string) - Required. Base64 encoded image string.
- **Response**: Updates the user profile and returns the updated data.

### 8. **Create Post**
- **URL**: `/api/v1/createPost`
- **Method**: `POST`
- **Parameters**: 
  - `title` (string) - Required.
  - `content` (string) - Required.
  - `author_id` (int) - Required.
  - `category` (string) - Optional.
- **Response**: Creates a new post and returns the post details. On failure, returns an appropriate error message.

### 9. **Get Posts**
- **URL**: `/api/v1/getPosts`
- **Method**: `POST`
- **Response**: Returns a list of posts, including details such as title, content, author, etc.

### 10. **Update Post**
- **URL**: `/api/v1/updatePost`
- **Method**: `POST`
- **Parameters**:
  - `post_id` (int) - Required. The ID of the post to update.
  - `title` (string) - Optional. New title of the post.
  - `content` (string) - Optional. New content of the post.
  - `category` (string) - Optional. New category of the post.
- **Response**: Updates the specified post and returns the updated post details. On failure, returns an appropriate error message.

### 11. **Create Product**
- **URL**: `/api/v1/createProduct`
- **Method**: `POST`
- **Parameters**:
  - `name` (string) - Required. The product name.
  - `description` (string) - Required. A description of the product.
  - `price` (float) - Required. The product's price.
  - `category_id` (int) - Required. The category ID to which the product belongs.
  - `stock` (int) - Required. The stock quantity of the product.
  - `image_url` (string) - Optional. URL for the product image.
- **Response**: Creates a new product and returns the product details. On failure, returns an appropriate error message.

### 12. **Save Product Variation**
- **URL**: `/api/v1/saveProductVariation`
- **Method**: `POST`
- **Parameters**:
  - `product_id` (int) - Required. The ID of the product for which the variation is to be added.
  - `variation_data` (array) - Required. An array of variation data (e.g., color, size).
- **Response**: Saves the product variation and returns the updated product details. On failure, returns an appropriate error message.

### 13. **Get Variable Product Details**
- **URL**: `/api/v1/get_variable_product_details`
- **Method**: `POST`
- **Parameters**:
  - `product_id` (int) - Required. The ID of the product to retrieve.
- **Response**: Returns details of a variable product, including variations such as color, size, and price.

## Error and Success Responses

- **Success Response**:
    ```json
    {
      "status": "success",
      "message": "User registered successfully",
      "data": {
        "id": 1,
        "username": "user1",
        "email": "user1@example.com"
      }
    }
    ```

- **Error Response**:
    ```json
    {
      "status": "error",
      "error_type": "ERROR",
      "message": "Username already exists"
    }
    ```

## Dependencies

- WordPress 5.0 or higher
- PHP 7.4 or higher
- JWT Authentication plugin (if you are using JWT for API authentication)
- WooCommerce (for product and product variation functionality)

## License

This plugin is released under the [GPL 2.0 License](https://opensource.org/licenses/GPL-2.0).

## Contributing

If you'd like to contribute to this plugin, feel free to fork the repository and submit pull requests. Ensure that you follow the coding standards for WordPress plugins.

---

### Note
Make sure to replace any example URLs (like `exampleplugin@restapi.com`) with the actual URLs of your plugin or its documentation.
