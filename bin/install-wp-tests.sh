#!/usr/bin/env bash
#
# WordPress Test Suite Installation Script
#
# Installs the WordPress test suite for running integration tests.
#
# Usage: bash scripts/install-wp-tests.sh <db-name> <db-user> <db-pass> [db-host] [wp-version] [skip-database-creation]

set -e

if [ $# -lt 3 ]; then
    echo "Usage: $0 <db-name> <db-user> <db-pass> [db-host] [wp-version] [skip-db]"
    exit 1
fi

DB_NAME=$1
DB_USER=$2
DB_PASS=$3
DB_HOST=${4-localhost}
WP_VERSION=${5-latest}
SKIP_DB_CREATE=${6-false}

TMPDIR=${TMPDIR-/tmp}
TMPDIR=$(echo "$TMPDIR" | sed -e "s/\/$//")

WP_TESTS_DIR=${WP_TESTS_DIR-$TMPDIR/wordpress-tests-lib}
WP_CORE_DIR=${WP_CORE_DIR-$TMPDIR/wordpress/}

download() {
    if [ "$(which curl)" ]; then
        curl -s "$1" > "$2"
    elif [ "$(which wget)" ]; then
        wget -nv -O "$2" "$1"
    fi
}

if [[ $WP_VERSION =~ ^[0-9]+\.[0-9]+\-(beta|RC)[0-9]+$ ]]; then
    WP_BRANCH=${WP_VERSION%\-*}
    WP_TESTS_TAG="branches/$WP_BRANCH"
elif [[ $WP_VERSION =~ ^[0-9]+\.[0-9]+$ ]]; then
    WP_TESTS_TAG="branches/$WP_VERSION"
elif [[ $WP_VERSION =~ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
    if [[ $WP_VERSION =~ [0-9]+\.[0-9]+\.[0] ]]; then
        WP_BRANCH=${WP_VERSION%\.0}
        WP_TESTS_TAG="branches/$WP_BRANCH"
    else
        WP_TESTS_TAG="tags/$WP_VERSION"
    fi
elif [[ $WP_VERSION == 'trunk' ]]; then
    WP_TESTS_TAG="trunk"
else
    download http://api.wordpress.org/core/version-check/1.7/ /tmp/wp-latest.json
    LATEST_VERSION=$(grep -o '"version":"[^"]*' /tmp/wp-latest.json | sed 's/"version":"//' | head -1)
    [ -z "$LATEST_VERSION" ] && { echo "Error: Could not determine latest WP version."; exit 1; }
    WP_TESTS_TAG="tags/$LATEST_VERSION"
fi

set_up_wp_tests_dir() {
    [ -d "$WP_TESTS_DIR" ] && rm -rf "$WP_TESTS_DIR"
    mkdir -p "$WP_TESTS_DIR"
    svn co --quiet "https://develop.svn.wordpress.org/${WP_TESTS_TAG}/tests/phpunit/includes/" "$WP_TESTS_DIR/includes"
    svn co --quiet "https://develop.svn.wordpress.org/${WP_TESTS_TAG}/tests/phpunit/data/" "$WP_TESTS_DIR/data"
}

install_wp() {
    [ -d "$WP_CORE_DIR" ] && rm -rf "$WP_CORE_DIR"
    mkdir -p "$WP_CORE_DIR"
    if [[ $WP_VERSION == 'trunk' ]]; then
        svn co --quiet https://develop.svn.wordpress.org/trunk/src/ "$WP_CORE_DIR"
    else
        if [ "$WP_VERSION" = 'latest' ]; then
            local ARCHIVE_URL='https://wordpress.org/latest.tar.gz'
        else
            local ARCHIVE_URL="https://wordpress.org/wordpress-$WP_VERSION.tar.gz"
        fi
        download "$ARCHIVE_URL" "$TMPDIR/wordpress.tar.gz"
        tar --strip-components=1 -zxmf "$TMPDIR/wordpress.tar.gz" -C "$WP_CORE_DIR"
    fi
}

install_test_suite() {
    if [ "$(uname -s)" = 'Darwin' ]; then
        local ioption='-i.bak'
    else
        local ioption='-i'
    fi
    download "https://develop.svn.wordpress.org/${WP_TESTS_TAG}/wp-tests-config-sample.php" "$WP_TESTS_DIR/wp-tests-config.php"
    sed $ioption "s:dirname( __FILE__ ) . '/src/':'$WP_CORE_DIR':" "$WP_TESTS_DIR/wp-tests-config.php"
    sed $ioption "s/youremptytestdbnamehere/$DB_NAME/" "$WP_TESTS_DIR/wp-tests-config.php"
    sed $ioption "s/yourusernamehere/$DB_USER/" "$WP_TESTS_DIR/wp-tests-config.php"
    sed $ioption "s/yourpasswordhere/$DB_PASS/" "$WP_TESTS_DIR/wp-tests-config.php"
    sed $ioption "s|localhost|${DB_HOST}|" "$WP_TESTS_DIR/wp-tests-config.php"
    rm -f "$WP_TESTS_DIR/wp-tests-config.php.bak"
}

create_db() {
    [ "$SKIP_DB_CREATE" = 'true' ] && return 0
    local EXTRA=""
    [ -n "$DB_PASS" ] && EXTRA=" -p$DB_PASS"
    mysqladmin drop "$DB_NAME" --force --silent --user="$DB_USER"$EXTRA --host="$DB_HOST" 2>/dev/null || true
    mysqladmin create "$DB_NAME" --user="$DB_USER"$EXTRA --host="$DB_HOST"
}

set_up_wp_tests_dir
install_wp
create_db
install_test_suite

echo "Installation complete. Tests dir: $WP_TESTS_DIR, Core: $WP_CORE_DIR"
