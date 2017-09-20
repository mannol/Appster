/*
 This example shows how to use sql module.

 The sql module is written using libpq, which works with postgresql server.
 libpq exposes an asynchronous API but, like any other async API, it's
 difficult to write comprehensible code with it.

 Appster apstracts the libpq async API and enables you to write fast, simple
 and readable code. You execute commands with as_sql() function which returns
 reply object. Then, you use that reply object to read the data returned by
 the server. After you are done with reading the reply data, free the reply
 object.
 */

/*
 You can use following query to setup the database for this example:

 CREATE TABLE playground (
    equip_id serial PRIMARY KEY,
    type varchar (50) NOT NULL,
    color varchar (25) NOT NULL,
    location varchar(25) check (location in ('north', 'south', 'west', 'east', 'northeast', 'southeast', 'southwest', 'northwest')),
    install_date date
 );

 INSERT INTO playground (type, color, location, install_date)
    VALUES ('swing', 'yellow', 'northwest', '2010-08-16');

 INSERT INTO playground (type, color, location, install_date)
    VALUES ('chair', 'red', 'east', '2011-09-21');
 */

#include <stdio.h>
#include "../appster.h"
#include "../module/sql.h"

int exec_sql(void* data) {
    sql_reply_t* rp;

    /* execute simple sql query */
    rp = as_sql("SELECT type, color, location, install_date FROM playground;");

    /*
     iterate over all rows

     This iteration is also an async operation because it doesn't wait for
     the whole reply to arrive, only a single row. Major speed burst right
     there. Specially for large queries...
     */
    for (; rp; rp = as_sql_next(rp)) {
        /*
         prints:
         'swing yellow northwest 2010-08-16'
         'chair red east 2011-09-21'
         */
        printf("%s %s %s %s\n",
               as_sql_string(rp, 0), as_sql_string(rp, 1),
               as_sql_string(rp, 2), as_sql_string(rp, 3));
    }

    /* execute 'complex' safe query (SQLi-safe) */
    rp = as_sqlf("SELECT %s, %s, %s, %s FROM %s;",
                 "type", "color", "location", "install_date", "playground");

    /*
     prints:
     'swing yellow northwest 2010-08-16'
     */
    printf("%s %s %s %s\n",
           as_sql_string(rp, 0), as_sql_string(rp, 1),
           as_sql_string(rp, 2), as_sql_string(rp, 3));

    /*
     if you are not going to iterate over all rows, you must stop the reply.
     */
    as_sql_stop(rp);

    return 200;
}

int main() {
    appster_schema_entry_t schema[] = {
        {"hello", 0, AVT_STRING, 1},
        {NULL}
    };

    appster_t* a = as_alloc(1);
    as_module_init(a, as_sql_module_init);

    as_add_route(a, "/sql", exec_sql, schema, NULL);
    as_add_sql("postgresql://postgres:asdf1234@localhost");

    as_listen_and_serve(a, "0.0.0.0", 8080, 2048);
    as_free(a);
    return 0;
}
