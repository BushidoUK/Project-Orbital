#!/usr/bin/env python3
"""
Project ORBITAL: Threat Actor & Infrastructure Map Generator
Parses Adversaries.md and TargetDevices.md, builds a NetworkX graph,
and exports an interactive PyVis visualization.
"""

import os
import re
import sys
import networkx as nx
from pyvis.network import Network


def split_outside_parentheses(text, delimiter):
    """
    Splits a string by a delimiter only when that delimiter is outside of parentheses.
    """
    parts = []
    current = []
    paren_depth = 0
    for char in text:
        if char == '(':
            paren_depth += 1
        elif char == ')':
            paren_depth -= 1
        
        if char == delimiter and paren_depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return parts


def normalize_name(name):
    """
    Normalizes threat actor, ORB network, and malware names to ensure graph consistency.
    Returns: (canonical_name, aliases_str, group_type)
    """
    name = name.replace("**", "").strip()
    name_lower = name.lower()
    
    # --- ACTORS (Threat Groups) ---
    if "unc2630" in name_lower or "apt5" in name_lower:
        return "UNC2630", "APT5", "Actor"
    if "apt15" in name_lower or "ke3chang" in name_lower or "nylon typhoon" in name_lower:
        return "APT15", "Ke3Chang, Nylon Typhoon", "Actor"
    if "unc5174" in name_lower:
        return "UNC5174", "", "Actor"
    if "apt31" in name_lower or "zirconium" in name_lower or "violet" in name_lower or "judgment panda" in name_lower:
        return "APT31", "Zirconium, Violet Typhoon, JUDGMENT PANDA", "Actor"
    if "silk typhoon" in name_lower or "murky panda" in name_lower:
        return "Silk Typhoon", "MURKY PANDA", "Actor"
    if "unc3886" in name_lower:
        return "UNC3886", "", "Actor"
    if "volt typhoon" in name_lower or "bronze silhouette" in name_lower:
        return "Volt Typhoon", "Bronze Silhouette", "Actor"
    if "uat-5918" in name_lower:
        return "UAT-5918", "", "Actor"
    if "uat-7810" in name_lower:
        return "UAT-7810", "", "Actor"
    if "flax typhoon" in name_lower or "ethereal panda" in name_lower:
        return "Flax Typhoon", "ETHEREAL PANDA", "Actor"
    if "weaver ant" in name_lower:
        return "Weaver Ant", "", "Actor"
        
    # --- INFRASTRUCTURE (ORB Networks / Clusters / Malware) ---
    if "spacehop" in name_lower or "orb3" in name_lower:
        return "SPACEHOP", "ORB3", "Infrastructure"
    if "purplehaze" in name_lower:
        return "PurpleHaze", "", "Infrastructure"
    if "florahox" in name_lower or "orb2" in name_lower:
        return "FLORAHOX", "ORB2", "Infrastructure"
    if "pakedge" in name_lower:
        return "PakEdge", "", "Infrastructure"
    if "orb28" in name_lower:
        return "ORB28", "", "Infrastructure"
    if "gobrat" in name_lower:
        return "GOBRAT", "", "Infrastructure"
    if "juniper infrastructure" in name_lower:
        return "Juniper Infrastructure", "", "Infrastructure"
    if "kv-botnet" in name_lower:
        return "KV-botnet", "", "Infrastructure"
    if "jdy" in name_lower:
        return "JDY botnet", "", "Infrastructure"
    if "lapdogs" in name_lower:
        # Extract potential parentheticals for custom aliases
        match = re.search(r"\(([^)]+)\)", name)
        alias = match.group(1) if match else ""
        return "LapDogs", alias, "Infrastructure"
    if "sparrow" in name_lower:
        return "Sparrow", "", "Infrastructure"
    if "unnamed orb network" in name_lower:
        return "Unnamed ORB network", "", "Infrastructure"
    if "wrthug" in name_lower:
        return "WrtHug", "", "Infrastructure"
    if "polaredge" in name_lower:
        return "PolarEdge", "", "Infrastructure"
    if "ayysshush" in name_lower:
        return "AyySSHush", "", "Infrastructure"
    if "zuorat" in name_lower:
        return "ZuoRAT", "", "Infrastructure"
    if "quad7" in name_lower or "fsynet" in name_lower:
        match = re.search(r"\(([^)]+)\)", name)
        alias = match.group(1) if match else ""
        if "fsynet" in name_lower:
            alias = f"FsyNet, {alias}" if alias else "FsyNet"
        return "Quad7", alias, "Infrastructure"
    if "vicioustrap" in name_lower:
        return "ViciousTrap", "", "Infrastructure"
        
    # --- DEFAULT PARSING ---
    match = re.match(r"^([^(]+)\s*\(([^)]+)\)", name)
    if match:
        main_name = match.group(1).strip()
        alias = match.group(2).strip()
        return main_name, alias, "Infrastructure"
        
    return name, "", "Infrastructure"


def parse_markdown_table(file_path):
    """
    Parses a markdown table file and returns a list of rows (lists of cell contents).
    """
    rows = []
    if not os.path.exists(file_path):
        print(f"Warning: File not found: {file_path}", file=sys.stderr)
        return rows
        
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("|") or not line.endswith("|"):
                continue
            
            # Extract cell values
            cells = [cell.strip() for cell in line.split("|")[1:-1]]
            
            # Skip separator line (| :--- | :--- |)
            if all(all(c in ":- " for c in cell) for cell in cells if cell):
                continue
                
            # Skip header line based on common header substrings
            if any("Threat Group" in cell or "Target Appliance" in cell for cell in cells):
                continue
                
            rows.append(cells)
    return rows


def add_or_update_node(G, node_id, **kwargs):
    """
    Safely adds a node or merges attributes with an existing node.
    """
    if G.has_node(node_id):
        for key, val in kwargs.items():
            if key == 'title':
                # Merge tooltips elegantly
                existing_title = G.nodes[node_id].get('title', '')
                if val and val not in existing_title:
                    if existing_title:
                        G.nodes[node_id]['title'] = f"{existing_title}<br>{val}"
                    else:
                        G.nodes[node_id]['title'] = val
            elif key == 'size':
                G.nodes[node_id]['size'] = max(G.nodes[node_id].get('size', 0), val)
            else:
                G.nodes[node_id][key] = val
    else:
        G.add_node(node_id, **kwargs)


def main():
    # Resolve directory paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    adversaries_path = os.path.join(base_dir, "Adversaries.md")
    targets_path = os.path.join(base_dir, "TargetDevices.md")
    output_html = os.path.join(base_dir, "index.html")

    print(f"Reading and parsing Markdown tables from '{base_dir}'...")
    adversary_rows = parse_markdown_table(adversaries_path)
    target_rows = parse_markdown_table(targets_path)

    # Initialize Directed Graph
    G = nx.DiGraph()

    # --- PROCESS ADVERSARIES.MD ---
    for row in adversary_rows:
        if len(row) < 2:
            continue
        raw_actor, raw_orbs = row[0], row[1]
        role_context = row[2] if len(row) > 2 else ""

        # Normalize Actor
        actor_name, actor_aliases, _ = normalize_name(raw_actor)
        
        # Build Actor node tooltip
        actor_tooltip = f"<b>Threat Group:</b> {actor_name}"
        if actor_aliases:
            actor_tooltip += f" ({actor_aliases})"
        if role_context:
            # Strip markdown links from context if any
            clean_context = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", role_context)
            actor_tooltip += f"<br><b>Context:</b> {clean_context}"

        add_or_update_node(
            G, actor_name,
            label=actor_name,
            group="Actor",
            color="#ff4757",
            size=25,
            title=actor_tooltip
        )

        # Normalize and split ORB networks
        orb_parts = split_outside_parentheses(raw_orbs, ',')
        for part in orb_parts:
            # Handle possible nested slashes (e.g. ORB2 / FLORAHOX)
            subparts = split_outside_parentheses(part, '/')
            for subpart in subparts:
                orb_name, orb_aliases, _ = normalize_name(subpart)
                
                orb_tooltip = f"<b>Infrastructure:</b> {orb_name}"
                if orb_aliases:
                    orb_tooltip += f" ({orb_aliases})"

                add_or_update_node(
                    G, orb_name,
                    label=orb_name,
                    group="Infrastructure",
                    color="#54a0ff",
                    size=20,
                    title=orb_tooltip
                )

                # Add directed edge from Actor utilizing ORB
                G.add_edge(
                    actor_name, orb_name,
                    label="utilizes",
                    title="utilizes",
                    color="#70a1ff",
                    arrows="to"
                )

    # --- PROCESS TARGETDEVICES.MD ---
    for row in target_rows:
        if len(row) < 2:
            continue
        raw_target, raw_threat_infra = row[0], row[1]

        target_name = raw_target.replace("**", "").strip()
        
        add_or_update_node(
            G, target_name,
            label=target_name,
            group="Target",
            color="#2ed573",
            size=20,
            title=f"<b>Target Appliance:</b> {target_name}"
        )

        # Split multiple targeters
        targeter_parts = split_outside_parentheses(raw_threat_infra, ',')
        for part in targeter_parts:
            subparts = split_outside_parentheses(part, '/')
            for subpart in subparts:
                norm_name, norm_aliases, type_group = normalize_name(subpart)
                
                # Check if it was parsed as Actor or Infrastructure
                if type_group == "Actor":
                    color = "#ff4757"
                    size = 25
                    group_label = "Threat Group"
                else:
                    color = "#54a0ff"
                    size = 20
                    group_label = "Infrastructure"

                tooltip = f"<b>{group_label}:</b> {norm_name}"
                if norm_aliases:
                    tooltip += f" ({norm_aliases})"

                add_or_update_node(
                    G, norm_name,
                    label=norm_name,
                    group=type_group,
                    color=color,
                    size=size,
                    title=tooltip
                )

                # Connect Target to ORB/Malware ("targeted_by")
                G.add_edge(
                    target_name, norm_name,
                    label="targeted_by",
                    title="targeted_by",
                    color="#a5b1c2",
                    arrows="to"
                )

    print(f"Graph assembled with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges.")

    # --- PYVIS EXPORT ---
    print("Generating PyVis Network...")
    net = Network(
        height="750px",
        width="100%",
        bgcolor="#222222",
        font_color="white",
        directed=True,
        select_menu=True,
        filter_menu=True,
        cdn_resources='remote'
    )

    # Load NetworkX representation into PyVis
    net.from_nx(G)
    net.toggle_physics(True)

    # Configure styling options
    net.set_options("""
    var options = {
      "nodes": {
        "font": {
          "face": "Outfit, Inter, sans-serif",
          "strokeWidth": 2,
          "strokeColor": "#222222"
        }
      },
      "edges": {
        "color": {
          "inherit": false
        },
        "smooth": {
          "type": "cubicBezier",
          "forceDirection": "horizontal",
          "roundness": 0.5
        },
        "arrows": {
          "to": {
            "enabled": true,
            "scaleFactor": 0.8
          }
        }
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -4000,
          "centralGravity": 0.25,
          "springLength": 150,
          "springConstant": 0.04,
          "damping": 0.09,
          "avoidOverlap": 0.6
        },
        "stabilization": {
          "enabled": true,
          "iterations": 1000,
          "updateInterval": 50,
          "onlyDynamicEdges": false,
          "fit": true
        }
      }
    }
    """)

    # Write HTML file
    # Generate HTML content in-memory
    print("Generating HTML content...")
    html_content = net.generate_html()

    print("Applying post-processing to HTML content...")

    # Update Title
    html_content = re.sub(
        r"<title>.*?</title>",
        "<title>Project ORBITAL: Threat Actor & Infrastructure Map</title>",
        html_content,
        flags=re.IGNORECASE
    )
    if "<title>" not in html_content:
        html_content = html_content.replace("<head>", "<head>\n<title>Project ORBITAL: Threat Actor & Infrastructure Map</title>")

    # Inject Premium Fonts & Custom Styles
    custom_css = """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap');
        
        body {
            font-family: 'Outfit', 'Segoe UI', sans-serif !important;
            background-color: #222222 !important;
        }
        
        div.vis-tooltip {
            background-color: rgba(30, 30, 30, 0.95) !important;
            border: 1px solid #444444 !important;
            color: #ffffff !important;
            font-family: 'Outfit', sans-serif !important;
            font-size: 13px !important;
            padding: 12px 16px !important;
            border-radius: 8px !important;
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.5) !important;
            max-width: 350px !important;
            line-height: 1.5 !important;
        }
        
        select, input, button {
            background-color: #2d2d2d !important;
            border: 1px solid #444 !important;
            color: #fff !important;
            border-radius: 4px !important;
            padding: 6px 12px !important;
            font-family: 'Outfit', sans-serif !important;
        }
        
        select:focus, input:focus {
            border-color: #54a0ff !important;
            outline: none !important;
        }
        
        .vis-configuration-wrapper {
            background-color: #222222 !important;
            color: #ffffff !important;
        }
    </style>
    """
    html_content = html_content.replace("</head>", f"{custom_css}\n</head>")

    # Custom Grid Layout Button and JavaScript
    # Custom Layout Toggle Button and JavaScript State Machine
    custom_js_ui = """
    <button id="layoutToggleButton">Switch to Grid View</button>
    <style>
        #layoutToggleButton {
            position: absolute;
            bottom: 30px;
            right: 30px;
            z-index: 999;
            background-color: #54a0ff;
            color: white;
            border-radius: 5px;
            font-weight: bold;
            cursor: pointer;
            border: none;
            padding: 10px 15px;
            font-family: 'Outfit', sans-serif;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);
            transition: background-color 0.3s ease, transform 0.1s;
        }
        #layoutToggleButton:hover {
            background-color: #70b0ff;
            transform: translateY(-1px);
        }
        #layoutToggleButton:active {
            transform: translateY(1px);
        }
    </style>
    <script type="text/javascript">
        var isGridLayout = false;

        document.getElementById('layoutToggleButton').addEventListener('click', function() {
            var btn = this;
            if (!isGridLayout) {
                // Switch to Grid View
                // 1. Turn off PyVis physics tracking
                network.setOptions({ physics: { enabled: false } });

                // 2. Extract all node IDs and collect the nodes
                var allNodes = nodes.get(nodes.getIds());

                // 3. Group them cleanly by their group attribute
                var groups = {};
                allNodes.forEach(function(node) {
                    var g = node.group || 'default';
                    if (!groups[g]) {
                        groups[g] = [];
                    }
                    groups[g].push(node.id);
                });

                // Arrange columns from right to left: Target on the right, Infrastructure in middle, Actor on the left
                var groupColumns = {
                    'Target': 400,
                    'Infrastructure': 0,
                    'Actor': -400
                };

                var ySpacing = 80;

                Object.keys(groups).forEach(function(g, colIdx) {
                    var x = groupColumns[g] !== undefined ? groupColumns[g] : (1 - colIdx) * 400;
                    var nodeList = groups[g];
                    
                    // Increment Y vertically down the screen centered around Y=0
                    var totalHeight = (nodeList.length - 1) * ySpacing;
                    var startY = -totalHeight / 2;

                    nodeList.forEach(function(nodeId, nodeIdx) {
                        var y = startY + (nodeIdx * ySpacing);
                        network.moveNode(nodeId, x, y);
                    });
                });

                // 4. Trigger smooth zoom-to-fit
                network.fit({ animation: true });

                // 5. Toggle UI state: Red color (#ff4757), text "Re-enable Physics View"
                btn.style.backgroundColor = '#ff4757';
                btn.innerText = 'Re-enable Physics View';
                
                // Add quick style override for hover state color changes
                btn.onmouseover = function() { btn.style.backgroundColor = '#ff6b81'; };
                btn.onmouseout = function() { btn.style.backgroundColor = '#ff4757'; };

                isGridLayout = true;
            } else {
                // Switch back to Unstructured Physics
                // 1. Turn PyVis physics back on
                network.setOptions({ physics: { enabled: true } });

                // 2. Trigger settling pass simulation
                network.stabilize();

                // 3. Reset viewport framing
                network.fit({ animation: true });

                // 4. Toggle UI state back: Sky Blue (#54a0ff), text "Switch to Grid View"
                btn.style.backgroundColor = '#54a0ff';
                btn.innerText = 'Switch to Grid View';
                
                btn.onmouseover = function() { btn.style.backgroundColor = '#70b0ff'; };
                btn.onmouseout = function() { btn.style.backgroundColor = '#54a0ff'; };

                isGridLayout = false;
            }
        });
    </script>
    """
    
    # Inject before the closing </body> tag
    html_content = html_content.replace("</body>", f"{custom_js_ui}\n</body>")

    # Write final index.html to disk
    try:
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"Successfully generated map: {output_html}")
    except Exception as e:
        print(f"Error writing output HTML: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
