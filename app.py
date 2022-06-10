from flask import Flask, render_template, request, g
import pickle
from main import get_node_type, get_type_map, filter_link, bfs, process_echart
import json

app = Flask(__name__)
nodes, links = pickle.load(open("./data/data.pkl", "rb"))


def get_data(index):
    if index == 1:
        # 团伙1
        source_list = ["Domain_c58c149eec59bb14b0c102a0f303d4c20366926b5c3206555d2937474124beb9",
                       "Domain_f3554b666038baffa5814c319d3053ee2c2eb30d31d0ef509a1a463386b69845"]
    elif index == 2:
        # 团伙2
        source_list = ["IP_400c19e584976ff2a35950659d4d148a3d146f1b71692468132b849b0eb8702c",
                       "Domain_b10f98a9b53806ccd3a5ee45676c7c09366545c5b12aa96955cde3953e7ad058"]
    elif index == 3:
        # 团伙3
        source_list = ["Domain_24acfd52f9ceb424d4a2643a832638ce1673b8689fa952d9010dd44949e6b1d9",
                       "Domain_9c72287c3f9bb38cb0186acf37b7054442b75ac32324dfd245aed46a03026de1",
                       "Domain_717aa5778731a1f4d6f0218dd3a27b114c839213b4af781427ac1e22dc9a7dea",
                       "Domain_8748687a61811032f0ed1dcdb57e01efef9983a6d9c236b82997b07477e66177",
                       "Whois_Phone_f4a84443fb72da27731660695dd00877e8ce25b264ec418504fface62cdcbbd7"]
    elif index == 4:
        # 团伙4
        source_list = ["IP_7e730b193c2496fc908086e8c44fc2dbbf7766e599fabde86a4bcb6afdaad66e",
                       "Cert_6724539e5c0851f37dcf91b7ac85cb35fcd9f8ba4df0107332c308aa53d63bdb"]
    elif index == 5:
        # 团伙5
        source_list = ["Whois_Phone_fd0a3f6712ff520edae7e554cb6dfb4bdd2af1e4a97a39ed9357b31b6888b4af",
                       "IP_21ce145cae6730a99300bf677b83bbe430cc0ec957047172e73659372f0031b8",
                       "Domain_7939d01c5b99c39d2a0f2b418f6060b917804e60c15309811ef4059257c0818a",
                       "Domain_587da0bac152713947db682a5443ef639e35f77a3b59e246e8a07c5eccae67e5"]
    else:
        return []
    return source_list


@app.route('/get_source_data')
def get_source_data():
    """
    not use
    """
    source_list = get_data(1)

    node_echart = []
    for i, source in enumerate(source_list):
        node_echart += [{"id": source, "category": get_node_type(nodes[source]["type"]),
                         "symbolSize": 12, "name": source, "expand": False, "start": True}]
    link_echart = []
    category_echart = []
    categories = sorted(get_type_map().items(), key=lambda kv: kv[1])
    for category in categories:
        category_echart += [{"name": category[0]}]
    echart = {"nodes": node_echart, "links": link_echart, "categories": category_echart}
    return echart


@app.route('/expand', methods=["POST"])
def expand():
    # 获得参数
    expand_node = request.json.get("expand_node")
    cur_nodes = request.json.get("nodes")
    cur_links = request.json.get("links")
    with open("./cache.json", "w") as f:
        json.dump({"nodes": cur_nodes, "links": cur_links}, f)
    node_set = set()
    for node in cur_nodes:
        node_set.add(node["id"])
    node_echart = []
    for node in cur_nodes:
        if node["id"] == expand_node:
            node["expand"] = True
        node_echart += [node]
    link_echart = [link for link in cur_links]
    # expand node
    for target, relation in filter_link(nodes, links, node_set, expand_node, links[expand_node]):
        if target in node_set:
            continue
        else:
            node_echart += [{"id": target, "category": get_node_type(nodes[target]["type"]),
                             "symbolSize": 12, "name": target, "expand": False, "start": False}]
            node_set.add(target)
        if "_reverse" in relation:
            link_echart += [{"source": target, "target": expand_node, "value": relation[:-8]}]
        else:
            link_echart += [{"source": expand_node, "target": target, "value": relation}]
        # 新添加点后会不会和原图上的结点产生其他联系
        for extra_target, extra_relation in links[target]:
            if extra_target in node_set and extra_target != expand_node:
                if "_reverse" in extra_relation:
                    link_echart += [{"source": extra_target, "target": target, "value": relation[:-8]}]
                else:
                    link_echart += [{"source": target, "target": extra_target, "value": relation}]
    return {"nodes": node_echart, "links": link_echart}


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/<index>')
def process(index):
    """
    展示第x个团伙
    """
    source_list = get_data(int(index))
    triple = bfs(nodes, links, source_list, hop_extra_limitation=True, k=3)
    echart = process_echart(nodes, triple, start_nodes=source_list)
    return echart


@app.route("/export", methods=["POST"])
def export():
    """
    导出echart数据结构, 保存到json
    """
    echart = request.json
    with open("./out.json", "w") as f:
        json.dump(echart, f)


@app.route("/revoke", methods=["POST"])
def revoke():
    """
    撤销上一次操作, 只能撤销一次(不能回到上一次再上一次)
    """
    with open("cache.json", 'r') as f:
        echart = json.load(f)
    return echart


if __name__ == '__main__':
    app.run()
