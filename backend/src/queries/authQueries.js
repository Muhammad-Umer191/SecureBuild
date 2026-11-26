const { User } = require('../models');

async function findUserByEmail(email, includePassword = false) {
  const query = User.findOne({ email });
  if (includePassword) query.select('+password');
  return query;
}

async function findUserById(id, includePassword = false) {
  const query = User.findById(id);
  if (includePassword) query.select('+password');
  return query;
}

async function createUser({ name, email, password }) {
  return User.create({ name, email, password });
}

async function updateUserPassword(user, newPassword) {
  user.password = newPassword;
  return user.save();
}

module.exports = {
  findUserByEmail,
  findUserById,
  createUser,
  updateUserPassword,
};
