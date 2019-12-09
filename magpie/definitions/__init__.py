def includeme(config):  # noqa: F811
    from magpie.utils import get_logger
    logger = get_logger(__name__)
    logger.info("Adding definitions...")
