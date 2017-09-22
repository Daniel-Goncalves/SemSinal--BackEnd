import yaml
import sys
import os

class ConfigHandler:

    # Le arquivo de configuracao
    config_file_stream = open(os.path.join(sys.path[0], "config.yaml"), "r")
    config = yaml.load(config_file_stream)

    mongodb_user = config["database"]["mongodb"]["user"]
    mongodb_password = config["database"]["mongodb"]["password"]
    mongodb_address = config["database"]["mongodb"]["address"]
    mongodb_db_name = config["database"]["mongodb"]["db_name"]
    mongodb_min_pool_size = config["database"]["mongodb"]["min_pool_size"]

    jwt_token = config["token"]["secret"]

    log_level = config["logging"]["level"]
    log_file = config["logging"]["filename"]

    hexagon_size = config["application"]["hexagon"]["size"]

    avgSstr_map_reduce_coll_name = config["application"]["map_reduce"]["avgsstr"]["coll_name"]
    ranking_map_reduce_coll_name = config["application"]["map_reduce"]["ranking"]["coll_name"]

    avgSstr_map_reduce_map_file = config["application"]["map_reduce"]["avgsstr"]["map_file"]
    avgSstr_map_reduce_reduce_file = config["application"]["map_reduce"]["avgsstr"]["reduce_file"]

    point_get_limit = int(config["application"]["point"]["get_limit"])
    point_get_default = int(config["application"]["point"]["get_default"])

    map_style_hex_delim = config["map"]["hex_style"]["sstr_delim"].split(",")
    map_style_hex_colors = config["map"]["hex_style"]["colors"].split(",")

    tech_filter_array = {
        "2G": [
            {"tech": 1},
            {"tech": 2},
            {"tech": 4},
            {"tech": 7},
            {"tech": 11},
            {"tech": 101}
        ],
        "3G": [
            {"tech": 3},
            {"tech": 5},
            {"tech": 6},
            {"tech": 7},
            {"tech": 8},
            {"tech": 9},
            {"tech": 10},
            {"tech": 12},
            {"tech": 14},
            {"tech": 15},
            {"tech": 103}
        ],
        "4G": [
            {"tech": 13},
            {"tech": 113}
        ]
    }

    config_file_stream.close()
