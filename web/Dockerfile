FROM nginx:1.30-alpine
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html styles.css app.js auth.js login.html admin-settings.html alert-settings.html notifications.html guide.html admin-users.html admin-nav.js users-admin.js users-admin.css atlas-tech.svg /usr/share/nginx/html/
EXPOSE 80
