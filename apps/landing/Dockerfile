# landing page preview (hero-only particle WebGL single HTML).
# rate-limited nginx + basic auth for friend previews.
# deploy/.htpasswd is generated at deploy time (not committed).
FROM nginx:1.27-alpine

COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY deploy/.htpasswd /etc/nginx/.htpasswd
COPY index.html video.html /usr/share/nginx/html/
COPY assets/ /usr/share/nginx/html/assets/
# Storyboard for operators (not required at runtime).
COPY VIDEO.md /usr/share/nginx/html/VIDEO.md

RUN chmod 644 /etc/nginx/.htpasswd

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["nginx", "-g", "daemon off;"]
