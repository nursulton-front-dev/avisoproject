// navbar.js

function renderNavbar() {
  fetch('/api/user') // Проверка: авторизован ли пользователь
    .then((res) => res.json())
    .then((data) => {
      const isLoggedIn = data.user;

      const navLinks = isLoggedIn
        ? `
        <a href="/dashboard">Задания</a>
        <a href="/create-task">Создать задание</a>
        <a href="/logout">Выйти</a>`
        : `
        <a href="/login">Войти</a>
        <a href="/register">Регистрация</a>`;

      const navbar = `
      <header>
        <h1>Aviso</h1>
        <nav>${navLinks}</nav>
      </header>`;

      document.body.insertAdjacentHTML('afterbegin', navbar);
    })
    .catch(() => {
      // В случае ошибки (например, неавторизован), покажем лог/рег
      const navbar = `
      <header>
        <h1>Aviso</h1>
        <nav>
          <a href="/login">Войти</a>
          <a href="/register">Регистрация</a>
        </nav>
      </header>`;
      document.body.insertAdjacentHTML('afterbegin', navbar);
    });
}

document.addEventListener("DOMContentLoaded", renderNavbar);
