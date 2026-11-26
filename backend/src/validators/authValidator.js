const Joi = require('joi');

const register = Joi.object({
  name: Joi.string().trim().min(1).max(100).required(),
  email: Joi.string().trim().email().required(),
  password: Joi.string().min(8).max(128).required(),
});

const login = Joi.object({
  email: Joi.string().trim().email().required(),
  password: Joi.string().required(),
});

const changePassword = Joi.object({
  currentPassword: Joi.string().required(),
  newPassword: Joi.string().min(8).max(128).invalid(Joi.ref('currentPassword')).required().messages({
    'any.invalid': 'newPassword must be different from currentPassword',
  }),
});

module.exports = { register, login, changePassword };
