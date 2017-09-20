#ifndef MODULE_SQL_H
#define MODULE_SQL_H

#include <stddef.h>

struct appster_module_s;
typedef struct sql_reply_s sql_reply_t;

int as_sql_module_init(struct appster_module_s* m);

/* Get last error information. */
const char* as_sql_errorstr();

/*
 Add a connection string to connect to. The accepted format is the same as in
 PQconnectdb's parameter. The string will be used to make and maintain
 connections to sql db. One connection is made per each string per thread, so
 to controll the amount of connections, one can call as_add_sql() multiple
 times. The connection usage is balanced with round-robin.
 */
void as_add_sql(const char* connstr);
/*
 Execute simple sql query. The sql_reply_t instance is returned that can be
 used to read reply data using appropriate API. See bellow for more info.
 In case of an error NULL reply is returned.
 */
sql_reply_t* as_sql(const char* query);
/*
 Execute complex formatted sql query. It's SQLi-safe, so you can feed it with
 untrusty data. As a precaution, this function can execute only a single command
 in a query!
 */
sql_reply_t* as_sqlf(const char* query, ...);
/*
 Receive the next row. If you are issuing the query and the query can return
 multiple rows, use this function to iterate over the rows. This function
 modifies the previous request so make sure to save any relevant data you might
 need.
 */
sql_reply_t* as_sql_next(sql_reply_t* prev);
/*
 Escape binary data for use in SQL query for bytea type. More info on link:
 https://www.postgresql.org/docs/9.6/static/libpq-exec.html under section
 PQescapeByteaConn(). This function allocates data that should be freed using
 free(). NOTE: the data CANNOT(!) be used in 2 different queries.
 */
char* as_sql_esc(const unsigned char* binary, size_t len);
/*
 Un-escape binary data. This function is the oposite of as_sql_esc().
 This function allocates data that should be freed using free().
 */
unsigned char* as_sql_unesc(const char* str, size_t* unesclen);
/*
 Once you have done working with the reply, make sure to free the allocated
 resources using this function.
 */
void as_sql_stop(sql_reply_t* reply);

/*
 Functions for accessing the row reply data. NOTE: each of these functions
 are meant to access a single row of data stored in reply object.
 */
const char* as_sql_string(sql_reply_t* reply, int field);
size_t as_sql_length(sql_reply_t* reply, int field);
double as_sql_number(sql_reply_t* reply, int field);
long long as_sql_integer(sql_reply_t* reply, int field);
unsigned long long as_sql_unsigned(sql_reply_t* reply, int field);
int as_sql_is_null(sql_reply_t* reply, int field);
/*
 If you are unsure about the field number for a certain field, use this function
 to get the field number using field name.
 */
int as_sql_field(sql_reply_t* reply, const char* field_name);

#endif /* MODULE_SQL_H */
