package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// D3Node represents a node in the D3.js force-directed graph
type D3Node struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Group    string `json:"group"`
	Size     int    `json:"size"`
	HasIssue bool   `json:"hasIssue"`
	Tooltip  string `json:"tooltip"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

// D3Link represents an edge in the D3.js force-directed graph
type D3Link struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Value    int    `json:"value"`
	Label    string `json:"label"`
	HasIssue bool   `json:"hasIssue"`
	Tooltip  string `json:"tooltip"`
}

// D3TimelineEvent represents an event for the D3.js timeline
type D3TimelineEvent struct {
	Time     float64 `json:"time"`
	Type     string  `json:"type"`
	Label    string  `json:"label"`
	Detail   string  `json:"detail"`
	Severity string  `json:"severity"`
}

// SankeyNode represents a node in the Sankey diagram
type SankeyNode struct {
	Name string `json:"name"`
}

// SankeyLink represents a flow in the Sankey diagram
type SankeyLink struct {
	Source int     `json:"source"`
	Target int     `json:"target"`
	Value  float64 `json:"value"`
}

// GetD3HTMLTemplate returns the complete HTML template with D3.js visualizations
func GetD3HTMLTemplate() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SD-WAN Network Triage Report</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/d3-sankey@0.12.3/dist/d3-sankey.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px; 
            line-height: 1.6;
            color: #2c3e50;
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: #f8f9fa;
            border-radius: 12px; 
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.95;
        }
        
        .content {
            padding: 30px;
        }
        
        /* Card System */
        .card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 16px rgba(0,0,0,0.15);
        }
        
        .card-header {
            display: flex;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid #e9ecef;
        }
        
        .card-header i {
            font-size: 1.8em;
            margin-right: 15px;
            color: #667eea;
        }
        
        .card-header h2 {
            font-size: 1.5em;
            color: #2c3e50;
            margin: 0;
        }
        
        .card-body {
            color: #495057;
        }
        
        /* Executive Summary */
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        }
        
        .stat-card h3 {
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-card.critical {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        }
        
        .stat-card.warning {
            background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);
            color: #000;
        }
        
        .stat-card.success {
            background: linear-gradient(135deg, #28a745 0%, #218838 100%);
        }
        
        /* Action Items */
        .action-item {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
            display: flex;
            align-items: start;
        }
        
        .action-item.critical {
            background: #f8d7da;
            border-left-color: #dc3545;
        }
        
        .action-item i {
            margin-right: 12px;
            margin-top: 2px;
            font-size: 1.2em;
        }
        
        .action-item strong {
            display: block;
            margin-bottom: 5px;
            color: #856404;
        }
        
        .action-item.critical strong {
            color: #721c24;
        }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            margin: 2px;
        }
        
        .badge-critical { background: #dc3545; color: white; }
        .badge-warning { background: #ffc107; color: #000; }
        .badge-info { background: #17a2b8; color: white; }
        .badge-success { background: #28a745; color: white; }
        
        /* Visualization Containers */
        #d3-network-diagram {
            width: 100%;
            height: 600px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            background: #fff;
            position: relative;
            overflow: hidden;
        }
        
        #d3-timeline {
            width: 100%;
            height: 400px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            background: #fff;
            margin-top: 20px;
        }
        
        #d3-traffic-flow {
            width: 100%;
            height: 500px;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            background: #fff;
            margin-top: 20px;
        }
        
        /* D3 Tooltip */
        .d3-tooltip {
            position: absolute;
            padding: 12px;
            background: rgba(0, 0, 0, 0.9);
            color: white;
            border-radius: 6px;
            pointer-events: none;
            font-size: 0.9em;
            line-height: 1.4;
            max-width: 300px;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }
        
        .d3-tooltip strong {
            display: block;
            margin-bottom: 5px;
            color: #667eea;
        }
        
        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        
        th {
            background: #667eea;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }
        
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #e9ecef;
        }
        
        tr:hover {
            background: #f8f9fa;
        }
        
        /* Collapsible Sections */
        .collapsible {
            cursor: pointer;
            padding: 12px;
            background: #e9ecef;
            border: none;
            text-align: left;
            width: 100%;
            border-radius: 6px;
            font-size: 1em;
            font-weight: 600;
            margin-top: 10px;
            transition: background 0.3s;
        }
        
        .collapsible:hover {
            background: #dee2e6;
        }
        
        .collapsible:after {
            content: '\\002B';
            float: right;
            font-weight: bold;
        }
        
        .collapsible.active:after {
            content: "\\2212";
        }
        
        .collapsible-content {
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.3s ease-out;
            background: #f8f9fa;
            border-radius: 0 0 6px 6px;
        }
        
        .collapsible-content-inner {
            padding: 15px;
        }
        
        /* Legend */
        .legend {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            font-size: 0.9em;
        }
        
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 4px;
            margin-right: 8px;
            border: 2px solid #333;
        }
        
        /* Footer */
        .footer {
            background: #2c3e50;
            color: white;
            padding: 30px;
            text-align: center;
            margin-top: 40px;
        }
        
        .footer p {
            margin: 5px 0;
            opacity: 0.9;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .summary-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 1.8em;
            }
            
            #d3-network-diagram,
            #d3-timeline,
            #d3-traffic-flow {
                height: 400px;
            }
        }
        
        /* Loading Spinner */
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><i class="fas fa-network-wired"></i> SD-WAN Network Triage Report</h1>
            <p>Comprehensive Network Analysis with Advanced Visualizations</p>
        </div>
        
        <div class="content">
`
}

// GetD3ScriptsTemplate returns the D3.js visualization scripts
func GetD3ScriptsTemplate() string {
	return `
        <script>
            // D3.js Force-Directed Network Graph
            function createNetworkDiagram(nodes, links) {
                const container = d3.select("#d3-network-diagram");
                const width = container.node().getBoundingClientRect().width;
                const height = 600;
                
                // Clear any existing content
                container.selectAll("*").remove();
                
                // Create SVG
                const svg = container.append("svg")
                    .attr("width", width)
                    .attr("height", height)
                    .attr("viewBox", [0, 0, width, height]);
                
                // Create zoom behavior
                const zoom = d3.zoom()
                    .scaleExtent([0.1, 4])
                    .on("zoom", (event) => {
                        g.attr("transform", event.transform);
                    });
                
                svg.call(zoom);
                
                // Create container group
                const g = svg.append("g");
                
                // Create tooltip
                const tooltip = d3.select("body").append("div")
                    .attr("class", "d3-tooltip")
                    .style("opacity", 0);
                
                // Color scale - Green for internal, Blue for router/gateway, Orange for external
                const colorScale = d3.scaleOrdinal()
                    .domain(["internal", "router", "external", "hop", "anomaly"])
                    .range(["#66cc66", "#6699ff", "#ff9933", "#9C27B0", "#dc3545"]);
                
                // Helper function to check if IP is in private ranges (RFC 1918)
                function isPrivateIP(ipParts) {
                    const [a, b, c, d] = ipParts;
                    return (
                        (a === 10) ||
                        (a === 172 && b >= 16 && b <= 31) ||
                        (a === 192 && b === 168)
                    );
                }
                
                // Helper function to categorize IP address
                function categorizeIP(ip) {
                    const parts = ip.split('.').map(Number);
                    if (parts.length !== 4 || parts.some(isNaN)) {
                        return "external"; // Invalid IP format
                    }
                    
                    // Check for Router/Gateway first (.1 or .254 within private ranges)
                    if ((parts[3] === 1 || parts[3] === 254) && isPrivateIP(parts)) {
                        return "router";
                    }
                    // Then check for general Internal (RFC 1918)
                    else if (isPrivateIP(parts)) {
                        return "internal";
                    }
                    // Otherwise, it's External
                    else {
                        return "external";
                    }
                }
                
                // Re-categorize nodes based on IP address
                nodes.forEach(node => {
                    if (!node.group || node.group === "internal" || node.group === "external") {
                        node.group = categorizeIP(node.id);
                    }
                });
                
                // Create force simulation
                const simulation = d3.forceSimulation(nodes)
                    .force("link", d3.forceLink(links).id(d => d.id).distance(150))
                    .force("charge", d3.forceManyBody().strength(-300))
                    .force("center", d3.forceCenter(width / 2, height / 2))
                    .force("collision", d3.forceCollide().radius(40));
                
                // Create links
                const link = g.append("g")
                    .selectAll("line")
                    .data(links)
                    .join("line")
                    .attr("stroke", d => d.hasIssue ? "#dc3545" : "#999")
                    .attr("stroke-opacity", 0.6)
                    .attr("stroke-width", d => Math.sqrt(d.value))
                    .attr("stroke-dasharray", d => d.hasIssue ? "5,5" : "0")
                    .on("mouseover", function(event, d) {
                        tooltip.transition().duration(200).style("opacity", .9);
                        tooltip.html(d.tooltip || d.label)
                            .style("left", (event.pageX + 10) + "px")
                            .style("top", (event.pageY - 28) + "px");
                    })
                    .on("mouseout", function() {
                        tooltip.transition().duration(500).style("opacity", 0);
                    });
                
                // Create link labels
                const linkLabel = g.append("g")
                    .selectAll("text")
                    .data(links)
                    .join("text")
                    .attr("font-size", 10)
                    .attr("fill", "#666")
                    .text(d => d.label);
                
                // Create nodes
                const node = g.append("g")
                    .selectAll("circle")
                    .data(nodes)
                    .join("circle")
                    .attr("r", d => d.size || 20)
                    .attr("fill", d => d.hasIssue ? "#dc3545" : colorScale(d.group))
                    .attr("stroke", "#fff")
                    .attr("stroke-width", 2)
                    .call(d3.drag()
                        .on("start", dragstarted)
                        .on("drag", dragged)
                        .on("end", dragended))
                    .on("mouseover", function(event, d) {
                        d3.select(this).attr("r", (d.size || 20) * 1.5);
                        tooltip.transition().duration(200).style("opacity", .9);
                        tooltip.html("<strong>" + d.label + "</strong><br/>" + (d.tooltip || ""))
                            .style("left", (event.pageX + 10) + "px")
                            .style("top", (event.pageY - 28) + "px");
                        
                        // Highlight connected nodes and edges
                        link.style("opacity", l => 
                            l.source.id === d.id || l.target.id === d.id ? 1 : 0.1);
                        node.style("opacity", n => 
                            n.id === d.id || links.some(l => 
                                (l.source.id === d.id && l.target.id === n.id) ||
                                (l.target.id === d.id && l.source.id === n.id)) ? 1 : 0.3);
                    })
                    .on("mouseout", function(event, d) {
                        d3.select(this).attr("r", d.size || 20);
                        tooltip.transition().duration(500).style("opacity", 0);
                        link.style("opacity", 0.6);
                        node.style("opacity", 1);
                    });
                
                // Create node labels
                const nodeLabel = g.append("g")
                    .selectAll("text")
                    .data(nodes)
                    .join("text")
                    .attr("font-size", 12)
                    .attr("font-weight", "bold")
                    .attr("fill", "#333")
                    .attr("text-anchor", "middle")
                    .attr("dy", -25)
                    .text(d => d.label);
                
                // Update positions on each tick
                simulation.on("tick", () => {
                    link
                        .attr("x1", d => d.source.x)
                        .attr("y1", d => d.source.y)
                        .attr("x2", d => d.target.x)
                        .attr("y2", d => d.target.y);
                    
                    linkLabel
                        .attr("x", d => (d.source.x + d.target.x) / 2)
                        .attr("y", d => (d.source.y + d.target.y) / 2);
                    
                    node
                        .attr("cx", d => d.x)
                        .attr("cy", d => d.y);
                    
                    nodeLabel
                        .attr("x", d => d.x)
                        .attr("y", d => d.y);
                });
                
                // Drag functions
                function dragstarted(event, d) {
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                }
                
                function dragged(event, d) {
                    d.fx = event.x;
                    d.fy = event.y;
                }
                
                function dragended(event, d) {
                    if (!event.active) simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }
            }
            
            // D3.js Timeline Visualization
            function createTimeline(events) {
                const container = d3.select("#d3-timeline");
                const width = container.node().getBoundingClientRect().width;
                const height = 400;
                const margin = {top: 40, right: 40, bottom: 60, left: 60};
                
                // Clear any existing content
                container.selectAll("*").remove();
                
                // Create SVG
                const svg = container.append("svg")
                    .attr("width", width)
                    .attr("height", height);
                
                const g = svg.append("g")
                    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");
                
                const innerWidth = width - margin.left - margin.right;
                const innerHeight = height - margin.top - margin.bottom;
                
                // Create tooltip
                const tooltip = d3.select("body").append("div")
                    .attr("class", "d3-tooltip")
                    .style("opacity", 0);
                
                // Scales
                const xScale = d3.scaleLinear()
                    .domain([0, d3.max(events, d => d.time)])
                    .range([0, innerWidth]);
                
                const colorScale = d3.scaleOrdinal()
                    .domain(["DNS", "TCP", "HTTP", "ARP", "TLS"])
                    .range(["#2196F3", "#4CAF50", "#FF9800", "#dc3545", "#9C27B0"]);
                
                // Axes
                const xAxis = d3.axisBottom(xScale)
                    .ticks(10)
                    .tickFormat(d => d.toFixed(1) + "s");
                
                g.append("g")
                    .attr("transform", "translate(0," + innerHeight + ")")
                    .call(xAxis)
                    .append("text")
                    .attr("x", innerWidth / 2)
                    .attr("y", 40)
                    .attr("fill", "#000")
                    .attr("font-weight", "bold")
                    .text("Time (seconds)");
                
                // Event markers
                const eventHeight = 30;
                const lanes = {};
                let currentLane = 0;
                
                events.forEach(event => {
                    if (!lanes[event.type]) {
                        lanes[event.type] = currentLane++;
                    }
                });
                
                g.selectAll("circle")
                    .data(events)
                    .join("circle")
                    .attr("cx", d => xScale(d.time))
                    .attr("cy", d => lanes[d.type] * eventHeight + eventHeight / 2)
                    .attr("r", 6)
                    .attr("fill", d => colorScale(d.type))
                    .attr("stroke", "#fff")
                    .attr("stroke-width", 2)
                    .on("mouseover", function(event, d) {
                        d3.select(this).attr("r", 10);
                        tooltip.transition().duration(200).style("opacity", .9);
                        tooltip.html("<strong>" + d.type + " @ " + d.time.toFixed(3) + "s</strong><br/>" + d.detail)
                            .style("left", (event.pageX + 10) + "px")
                            .style("top", (event.pageY - 28) + "px");
                    })
                    .on("mouseout", function() {
                        d3.select(this).attr("r", 6);
                        tooltip.transition().duration(500).style("opacity", 0);
                    });
                
                // Lane labels
                Object.keys(lanes).forEach(type => {
                    g.append("text")
                        .attr("x", -10)
                        .attr("y", lanes[type] * eventHeight + eventHeight / 2)
                        .attr("text-anchor", "end")
                        .attr("alignment-baseline", "middle")
                        .attr("font-size", 12)
                        .attr("fill", colorScale(type))
                        .attr("font-weight", "bold")
                        .text(type);
                });
            }
            
            // D3.js Sankey Diagram for Traffic Flow
            function createSankeyDiagram(data) {
                const container = d3.select("#d3-traffic-flow");
                const width = container.node().getBoundingClientRect().width;
                const height = 500;
                const margin = {top: 10, right: 10, bottom: 10, left: 10};
                
                // Clear any existing content
                container.selectAll("*").remove();
                
                // Create SVG
                const svg = container.append("svg")
                    .attr("width", width)
                    .attr("height", height);
                
                const g = svg.append("g")
                    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");
                
                const innerWidth = width - margin.left - margin.right;
                const innerHeight = height - margin.top - margin.bottom;
                
                // Create Sankey generator
                const sankey = d3.sankey()
                    .nodeWidth(15)
                    .nodePadding(10)
                    .extent([[1, 1], [innerWidth - 1, innerHeight - 5]]);
                
                const {nodes, links} = sankey(data);
                
                // Create tooltip
                const tooltip = d3.select("body").append("div")
                    .attr("class", "d3-tooltip")
                    .style("opacity", 0);
                
                // Color scale
                const color = d3.scaleOrdinal(d3.schemeCategory10);
                
                // Draw links
                g.append("g")
                    .selectAll("path")
                    .data(links)
                    .join("path")
                    .attr("d", d3.sankeyLinkHorizontal())
                    .attr("stroke", d => color(d.source.name))
                    .attr("stroke-width", d => Math.max(1, d.width))
                    .attr("fill", "none")
                    .attr("opacity", 0.5)
                    .on("mouseover", function(event, d) {
                        d3.select(this).attr("opacity", 0.8);
                        tooltip.transition().duration(200).style("opacity", .9);
                        tooltip.html("<strong>" + d.source.name + " → " + d.target.name + "</strong><br/>" +
                                   "Traffic: " + (d.value / (1024*1024)).toFixed(2) + " MB")
                            .style("left", (event.pageX + 10) + "px")
                            .style("top", (event.pageY - 28) + "px");
                    })
                    .on("mouseout", function() {
                        d3.select(this).attr("opacity", 0.5);
                        tooltip.transition().duration(500).style("opacity", 0);
                    });
                
                // Draw nodes
                g.append("g")
                    .selectAll("rect")
                    .data(nodes)
                    .join("rect")
                    .attr("x", d => d.x0)
                    .attr("y", d => d.y0)
                    .attr("height", d => d.y1 - d.y0)
                    .attr("width", d => d.x1 - d.x0)
                    .attr("fill", d => color(d.name))
                    .attr("stroke", "#000")
                    .on("mouseover", function(event, d) {
                        tooltip.transition().duration(200).style("opacity", .9);
                        tooltip.html("<strong>" + d.name + "</strong><br/>" +
                                   "Total: " + (d.value / (1024*1024)).toFixed(2) + " MB")
                            .style("left", (event.pageX + 10) + "px")
                            .style("top", (event.pageY - 28) + "px");
                    })
                    .on("mouseout", function() {
                        tooltip.transition().duration(500).style("opacity", 0);
                    });
                
                // Add node labels
                g.append("g")
                    .selectAll("text")
                    .data(nodes)
                    .join("text")
                    .attr("x", d => d.x0 < innerWidth / 2 ? d.x1 + 6 : d.x0 - 6)
                    .attr("y", d => (d.y1 + d.y0) / 2)
                    .attr("dy", "0.35em")
                    .attr("text-anchor", d => d.x0 < innerWidth / 2 ? "start" : "end")
                    .attr("font-size", 12)
                    .text(d => d.name);
            }
            
            // Collapsible sections
            document.addEventListener('DOMContentLoaded', function() {
                const collapsibles = document.getElementsByClassName("collapsible");
                for (let i = 0; i < collapsibles.length; i++) {
                    collapsibles[i].addEventListener("click", function() {
                        this.classList.toggle("active");
                        const content = this.nextElementSibling;
                        if (content.style.maxHeight) {
                            content.style.maxHeight = null;
                        } else {
                            content.style.maxHeight = content.scrollHeight + "px";
                        }
                    });
                }
            });
            
            // Toggle action visibility for finding-specific action items
            function toggleAction(button) {
                const currentRow = button.closest('tr');
                const actionRow = currentRow.nextElementSibling;
                if (actionRow && actionRow.classList.contains('action-row')) {
                    const isVisible = actionRow.style.display !== 'none';
                    actionRow.style.display = isVisible ? 'none' : '';
                    button.textContent = isVisible ? 'Show Action' : 'Hide Action';
                    button.style.background = isVisible ? '#6c757d' : '#28a745';
                }
            }
        </script>
`
}

// GenerateActionItems generates HTML for actionable recommendations
func GenerateActionItems(criticalIssues, performanceIssues, securityConcerns int) string {
	html := `<div class="card">
    <div class="card-header">
        <i class="fas fa-tasks"></i>
        <h2>Recommended Actions</h2>
    </div>
    <div class="card-body">`

	if criticalIssues > 0 {
		html += `
        <div class="action-item critical">
            <i class="fas fa-exclamation-triangle"></i>
            <div>
                <strong>CRITICAL: Investigate Network Anomalies</strong>
                You have ` + fmt.Sprintf("%d", criticalIssues) + ` critical issues detected (DNS anomalies, ARP conflicts).
                <ul style="margin-top: 8px; margin-left: 20px;">
                    <li>Review DNS server configurations and check for DNS poisoning</li>
                    <li>Identify devices with MAC address conflicts and remove duplicates</li>
                    <li>Scan affected systems for malware or unauthorized access</li>
                    <li>Contact your network security team immediately</li>
                </ul>
            </div>
        </div>`
	}

	if performanceIssues > 5 {
		html += `
        <div class="action-item warning">
            <i class="fas fa-chart-line"></i>
            <div>
                <strong>Performance Optimization Needed</strong>
                Detected ` + fmt.Sprintf("%d", performanceIssues) + ` performance issues including TCP retransmissions and high latency.
                <ul style="margin-top: 8px; margin-left: 20px;">
                    <li>Check network links for congestion or hardware issues</li>
                    <li>Review QoS policies on routers and switches</li>
                    <li>Consider upgrading bandwidth for high-traffic links</li>
                    <li>Investigate applications causing retransmissions</li>
                </ul>
            </div>
        </div>`
	}

	if securityConcerns > 0 {
		html += `
        <div class="action-item warning">
            <i class="fas fa-shield-alt"></i>
            <div>
                <strong>Security Review Required</strong>
                Found ` + fmt.Sprintf("%d", securityConcerns) + ` security concerns (suspicious traffic, expired certificates).
                <ul style="margin-top: 8px; margin-left: 20px;">
                    <li>Review and renew expired TLS certificates</li>
                    <li>Investigate traffic to suspicious ports</li>
                    <li>Update firewall rules to block unauthorized access</li>
                    <li>Conduct security audit of affected systems</li>
                </ul>
            </div>
        </div>`
	}

	if criticalIssues == 0 && performanceIssues <= 5 && securityConcerns == 0 {
		html += `
        <div class="action-item" style="background: #d4edda; border-left-color: #28a745;">
            <i class="fas fa-check-circle" style="color: #28a745;"></i>
            <div>
                <strong>Network Health: Good</strong>
                No critical issues detected. Continue monitoring network performance and security.
                <ul style="margin-top: 8px; margin-left: 20px;">
                    <li>Maintain regular PCAP captures for baseline comparison</li>
                    <li>Keep network equipment firmware up to date</li>
                    <li>Review security policies quarterly</li>
                </ul>
            </div>
        </div>`
	}

	html += `
    </div>
</div>`

	return html
}

// EscapeHTML escapes special HTML characters
func EscapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

// WriteHTMLFile writes the complete HTML report to a file
func WriteHTMLFile(filename, content string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(content)
	return err
}

// ConvertToD3Nodes converts path stats to D3 nodes format
func ConvertToD3Nodes(nodes interface{}) (string, error) {
	jsonData, err := json.Marshal(nodes)
	if err != nil {
		return "", err
	}
	return string(jsonData), nil
}
