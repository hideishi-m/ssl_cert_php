FROM php:8.3-cli
RUN echo 'phar.readonly = 0' > /usr/local/etc/php/php.ini
RUN mkdir -p /usr/src
WORKDIR /usr/src
ENTRYPOINT [ "php", "makephar.php" ]
