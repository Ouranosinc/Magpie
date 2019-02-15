from magpie.definitions.sqlalchemy_definitions import Inspector


def has_column(context, table_name, column_name):
    inspector = Inspector.from_engine(context.connection.engine)
    for column in inspector.get_columns(table_name=table_name):
        if column_name in column['name']:
            return True
    return False
