// SD-WAN Triage Report Visualizations - Simplified Implementation
// Clean, minimal D3.js force-directed graph

// Theme-aware color utilities
function getThemeColors() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        primary: '#3b82f6',
        success: '#10b981',
        warning: '#f59e0b',
        danger: '#ef4444',
        text: isDark ? '#f1f5f9' : '#1e293b',
        background: isDark ? '#1e293b' : '#ffffff',
        border: isDark ? '#334155' : '#e2e8f0'
    };
}

// Network Diagram - Simple, Clean Force-Directed Graph
function createNetworkDiagram(container, data) {
    // Clear existing content
    d3.select(container).selectAll("*").remove();
    
    // Validate data
    if (!data || !data.nodes || !data.links || data.nodes.length === 0) {
        container.innerHTML = '<div style="padding: 40px; text-align: center; color: #64748b;">No network data available</div>';
        return;
    }
    
    // Dimensions
    const width = container.clientWidth || 800;
    const height = 500;
    
    // Create SVG with white background
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height)
        .style("background", "#ffffff")
        .style("border", "1px solid #e0e0e0")
        .style("border-radius", "8px");
    
    // Create main group for zoom/pan
    const g = svg.append("g");
    
    // Add zoom behavior
    svg.call(d3.zoom()
        .scaleExtent([0.5, 3])
        .on("zoom", (event) => g.attr("transform", event.transform)));
    
    // Define arrowhead marker - CRITICAL: markerUnits prevents scaling issues
    svg.append("defs")
        .append("marker")
        .attr("id", "arrow")
        .attr("viewBox", "0 -5 10 10")
        .attr("refX", 12)
        .attr("refY", 0)
        .attr("markerWidth", 3)
        .attr("markerHeight", 3)
        .attr("markerUnits", "strokeWidth")
        .attr("orient", "auto")
        .append("path")
        .attr("d", "M0,-5L10,0L0,5")
        .attr("fill", "#94a3b8");
    
    // Simple color mapping
    const nodeColors = {
        "internal": "#10b981",
        "router": "#3b82f6",
        "external": "#f59e0b",
        "anomaly": "#ef4444"
    };
    
    // Create tooltip
    const tooltip = d3.select("body")
        .append("div")
        .attr("class", "d3-tooltip")
        .style("position", "absolute")
        .style("opacity", 0)
        .style("background", "rgba(0,0,0,0.8)")
        .style("color", "white")
        .style("padding", "8px 12px")
        .style("border-radius", "4px")
        .style("font-size", "12px")
        .style("pointer-events", "none")
        .style("z-index", "10000");
    
    // Simple force simulation
    const simulation = d3.forceSimulation(data.nodes)
        .force("link", d3.forceLink(data.links).id(d => d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-300))
        .force("center", d3.forceCenter(width / 2, height / 2))
        .force("collision", d3.forceCollide().radius(30));
    
    // Draw links
    const link = g.append("g")
        .selectAll("line")
        .data(data.links)
        .join("line")
        .attr("stroke", d => d.hasIssue ? "#ef4444" : "#cbd5e1")
        .attr("stroke-width", d => {
            const bytes = d.value || 0;
            if (bytes > 10000000) return 3;
            if (bytes > 1000000) return 2;
            return 1;
        })
        .attr("stroke-dasharray", d => d.hasIssue ? "4,4" : "0")
        .attr("marker-end", "url(#arrow)");
    
    // Draw nodes
    const node = g.append("g")
        .selectAll("circle")
        .data(data.nodes)
        .join("circle")
        .attr("r", d => d.group === "router" ? 10 : 8)
        .attr("fill", d => nodeColors[d.group] || "#94a3b8")
        .attr("stroke", "#fff")
        .attr("stroke-width", 2)
        .style("cursor", "pointer")
        .call(d3.drag()
            .on("start", dragStarted)
            .on("drag", dragged)
            .on("end", dragEnded))
        .on("mouseover", function(event, d) {
            d3.select(this)
                .attr("stroke-width", 3)
                .attr("r", d.group === "router" ? 12 : 10);
            
            tooltip.transition().duration(200).style("opacity", 1);
            tooltip.html(`
                <strong>${d.id}</strong><br/>
                Type: ${d.group}<br/>
                ${d.bytes ? `Traffic: ${formatBytes(d.bytes)}` : ''}
            `)
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px");
        })
        .on("mouseout", function(event, d) {
            d3.select(this)
                .attr("stroke-width", 2)
                .attr("r", d.group === "router" ? 10 : 8);
            
            tooltip.transition().duration(500).style("opacity", 0);
        });
    
    // Add labels
    const label = g.append("g")
        .selectAll("text")
        .data(data.nodes)
        .join("text")
        .text(d => d.id)
        .attr("font-size", "11px")
        .attr("dx", 12)
        .attr("dy", 4)
        .attr("fill", "#1e293b")
        .attr("stroke", "#fff")
        .attr("stroke-width", 3)
        .attr("paint-order", "stroke")
        .style("pointer-events", "none");
    
    // Update positions on simulation tick
    simulation.on("tick", () => {
        link
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);
        
        node
            .attr("cx", d => d.x)
            .attr("cy", d => d.y);
        
        label
            .attr("x", d => d.x)
            .attr("y", d => d.y);
    });
    
    // Drag functions
    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    
    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
    
    // Helper function
    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }
    
    // Add simple legend
    const legend = svg.append("g")
        .attr("transform", `translate(20, ${height - 120})`);
    
    legend.append("rect")
        .attr("width", 160)
        .attr("height", 110)
        .attr("fill", "rgba(255,255,255,0.95)")
        .attr("stroke", "#e0e0e0")
        .attr("rx", 4);
    
    const legendItems = [
        { label: "Internal", color: "#10b981" },
        { label: "Router", color: "#3b82f6" },
        { label: "External", color: "#f59e0b" },
        { label: "Anomaly", color: "#ef4444" }
    ];
    
    legendItems.forEach((item, i) => {
        const lg = legend.append("g")
            .attr("transform", `translate(10, ${i * 25 + 15})`);
        
        lg.append("circle")
            .attr("r", 6)
            .attr("fill", item.color)
            .attr("stroke", "#fff")
            .attr("stroke-width", 1);
        
        lg.append("text")
            .attr("x", 15)
            .attr("y", 4)
            .attr("font-size", "12px")
            .attr("fill", "#1e293b")
            .text(item.label);
    });
}

// Timeline Visualization
function createTimeline(container, data) {
    d3.select(container).selectAll("*").remove();
    
    // Data is an array directly, not data.events
    if (!data || !Array.isArray(data) || data.length === 0) {
        container.innerHTML = '<div style="padding: 40px; text-align: center; color: #64748b;"><i class="fas fa-clock" style="font-size: 2rem; margin-bottom: 12px; display: block;"></i>No timeline events available<br/><small style="color: #9ca3af;">Timeline events are generated from network activity patterns</small></div>';
        return;
    }
    
    const width = container.clientWidth || 800;
    const height = 400;
    const margin = {top: 40, right: 40, bottom: 60, left: 120};
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height)
        .style("background", "#ffffff")
        .style("border", "1px solid #e0e0e0")
        .style("border-radius", "8px");
    
    const g = svg.append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);
    
    // Parse timestamps - data comes as array with timestamp, type, source, target, detail
    const events = data.map(e => ({
        time: new Date(e.timestamp * 1000),
        type: e.type || 'unknown',
        source: e.source || '',
        target: e.target || '',
        detail: e.detail || ''
    }));
    
    const xScale = d3.scaleTime()
        .domain(d3.extent(events, d => d.time))
        .range([0, chartWidth]);
    
    const eventTypes = [...new Set(events.map(e => e.type))];
    const yScale = d3.scaleBand()
        .domain(eventTypes)
        .range([0, chartHeight])
        .padding(0.3);
    
    const colorScale = d3.scaleOrdinal()
        .domain(eventTypes)
        .range(['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899']);
    
    // Add axes
    g.append("g")
        .attr("transform", `translate(0,${chartHeight})`)
        .call(d3.axisBottom(xScale).ticks(6))
        .selectAll("text")
        .style("font-size", "11px");
    
    g.append("g")
        .call(d3.axisLeft(yScale))
        .selectAll("text")
        .style("font-size", "11px");
    
    // Add events
    g.selectAll(".event")
        .data(events)
        .join("circle")
        .attr("class", "event")
        .attr("cx", d => xScale(d.time))
        .attr("cy", d => yScale(d.type) + yScale.bandwidth() / 2)
        .attr("r", 5)
        .attr("fill", d => colorScale(d.type))
        .attr("stroke", "#fff")
        .attr("stroke-width", 2)
        .style("cursor", "pointer")
        .on("mouseover", function(event, d) {
            d3.select(this).attr("r", 7);
            let tooltipHtml = '<strong>' + d.type + '</strong><br/>';
            if (d.source && d.target) tooltipHtml += d.source + ' -> ' + d.target + '<br/>';
            if (d.detail) tooltipHtml += d.detail + '<br/>';
            tooltipHtml += d.time.toLocaleString();
            showTooltip(event, tooltipHtml);
        })
        .on("mouseout", function() {
            d3.select(this).attr("r", 5);
            hideTooltip();
        });
    
    // Add title
    svg.append("text")
        .attr("x", width / 2)
        .attr("y", 20)
        .attr("text-anchor", "middle")
        .style("font-size", "14px")
        .style("font-weight", "600")
        .text("Event Timeline");
}

// Sankey Diagram for Traffic Flows
function createSankeyDiagram(container, data) {
    d3.select(container).selectAll("*").remove();
    
    // Data comes with nodes having 'name' property and links with source/target as indices
    if (!data || !data.nodes || !data.links || data.nodes.length === 0 || data.links.length === 0) {
        container.innerHTML = '<div style="padding: 40px; text-align: center; color: #64748b;"><i class="fas fa-stream" style="font-size: 2rem; margin-bottom: 12px; display: block;"></i>No traffic flow data available<br/><small style="color: #9ca3af;">Traffic flow diagram requires captured network flows</small></div>';
        return;
    }
    
    const width = container.clientWidth || 800;
    const height = 400;
    const margin = {top: 40, right: 40, bottom: 40, left: 40};
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height)
        .style("background", "#ffffff")
        .style("border", "1px solid #e0e0e0")
        .style("border-radius", "8px");
    
    const g = svg.append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);
    
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;
    
    // Nodes have 'name' property from Go code
    const nodes = data.nodes;
    const links = data.links;
    
    // Position nodes evenly across the width
    const nodeWidth = 140;
    const nodeHeight = 50;
    const nodeSpacing = chartWidth / (nodes.length + 1);
    
    // Calculate node positions
    nodes.forEach((node, i) => {
        node.x = nodeSpacing * (i + 1) - nodeWidth / 2;
        node.y = chartHeight / 2 - nodeHeight / 2;
    });
    
    // Color scale for nodes
    const colors = ['#3b82f6', '#8b5cf6', '#10b981'];
    
    // Draw links first (behind nodes)
    links.forEach(link => {
        const sourceNode = nodes[link.source];
        const targetNode = nodes[link.target];
        
        if (sourceNode && targetNode) {
            const x1 = sourceNode.x + nodeWidth;
            const y1 = sourceNode.y + nodeHeight / 2;
            const x2 = targetNode.x;
            const y2 = targetNode.y + nodeHeight / 2;
            const midX = (x1 + x2) / 2;
            
            const path = d3.path();
            path.moveTo(x1, y1);
            path.bezierCurveTo(midX, y1, midX, y2, x2, y2);
            
            // Scale link width based on value
            const maxValue = d3.max(links, l => l.value) || 1;
            const linkWidth = Math.max(4, (link.value / maxValue) * 40);
            
            g.append("path")
                .attr("d", path.toString())
                .attr("fill", "none")
                .attr("stroke", "#94a3b8")
                .attr("stroke-width", linkWidth)
                .attr("opacity", 0.5)
                .style("cursor", "pointer")
                .on("mouseover", function(event) {
                    d3.select(this).attr("opacity", 0.8).attr("stroke", "#3b82f6");
                    showTooltip(event, '<strong>' + sourceNode.name + ' -> ' + targetNode.name + '</strong><br/>Traffic: ' + formatBytesSankey(link.value));
                })
                .on("mouseout", function() {
                    d3.select(this).attr("opacity", 0.5).attr("stroke", "#94a3b8");
                    hideTooltip();
                });
        }
    });
    
    // Draw nodes
    nodes.forEach((node, i) => {
        const nodeG = g.append("g")
            .attr("transform", 'translate(' + node.x + ', ' + node.y + ')');
        
        nodeG.append("rect")
            .attr("width", nodeWidth)
            .attr("height", nodeHeight)
            .attr("fill", colors[i % colors.length])
            .attr("rx", 6)
            .style("cursor", "pointer");
        
        nodeG.append("text")
            .attr("x", nodeWidth / 2)
            .attr("y", nodeHeight / 2 + 5)
            .attr("text-anchor", "middle")
            .attr("fill", "#fff")
            .style("font-size", "12px")
            .style("font-weight", "600")
            .text(node.name);
    });
    
    // Add title
    svg.append("text")
        .attr("x", width / 2)
        .attr("y", 20)
        .attr("text-anchor", "middle")
        .style("font-size", "14px")
        .style("font-weight", "600")
        .text("Traffic Flow Diagram");
    
    function formatBytesSankey(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
    }
}

// RTT Histogram
function createRTTHistogram(container, data) {
    d3.select(container).selectAll("*").remove();
    
    // Data comes as array of {bucket: "0-10ms", count: N} objects from Go
    if (!data || !Array.isArray(data) || data.length === 0) {
        container.innerHTML = '<div style="padding: 40px; text-align: center; color: #64748b;"><i class="fas fa-chart-bar" style="font-size: 2rem; margin-bottom: 12px; display: block;"></i>No RTT data available<br/><small style="color: #9ca3af;">RTT distribution requires TCP flow analysis data</small></div>';
        return;
    }
    
    const width = container.clientWidth || 800;
    const height = 400;
    const margin = {top: 40, right: 40, bottom: 80, left: 60};
    const chartWidth = width - margin.left - margin.right;
    const chartHeight = height - margin.top - margin.bottom;
    
    const svg = d3.select(container)
        .append("svg")
        .attr("width", width)
        .attr("height", height)
        .style("background", "#ffffff")
        .style("border", "1px solid #e0e0e0")
        .style("border-radius", "8px");
    
    const g = svg.append("g")
        .attr("transform", `translate(${margin.left},${margin.top})`);
    
    // Use bucket labels for x-axis (categorical)
    const buckets = data.map(d => d.bucket);
    const counts = data.map(d => d.count);
    
    const xScale = d3.scaleBand()
        .domain(buckets)
        .range([0, chartWidth])
        .padding(0.2);
    
    const yScale = d3.scaleLinear()
        .domain([0, d3.max(counts) || 1])
        .range([chartHeight, 0]);
    
    // Color scale based on RTT severity
    const colorScale = function(bucket) {
        if (bucket.includes('0-10') || bucket.includes('10-50')) return '#22c55e';
        if (bucket.includes('50-100') || bucket.includes('100-200')) return '#f59e0b';
        return '#ef4444';
    };
    
    // Add x-axis
    g.append("g")
        .attr("transform", `translate(0,${chartHeight})`)
        .call(d3.axisBottom(xScale))
        .selectAll("text")
        .style("font-size", "11px")
        .attr("transform", "rotate(-30)")
        .attr("text-anchor", "end");
    
    // Add y-axis
    g.append("g")
        .call(d3.axisLeft(yScale).ticks(5))
        .selectAll("text")
        .style("font-size", "11px");
    
    // Add bars
    g.selectAll(".bar")
        .data(data)
        .join("rect")
        .attr("class", "bar")
        .attr("x", d => xScale(d.bucket))
        .attr("y", d => yScale(d.count))
        .attr("width", xScale.bandwidth())
        .attr("height", d => chartHeight - yScale(d.count))
        .attr("fill", d => colorScale(d.bucket))
        .attr("opacity", 0.85)
        .attr("rx", 4)
        .style("cursor", "pointer")
        .on("mouseover", function(event, d) {
            d3.select(this).attr("opacity", 1);
            showTooltip(event, '<strong>RTT: ' + d.bucket + '</strong><br/>Count: ' + d.count + ' flows');
        })
        .on("mouseout", function() {
            d3.select(this).attr("opacity", 0.85);
            hideTooltip();
        });
    
    // Add value labels on bars
    g.selectAll(".label")
        .data(data)
        .join("text")
        .attr("class", "label")
        .attr("x", d => xScale(d.bucket) + xScale.bandwidth() / 2)
        .attr("y", d => yScale(d.count) - 5)
        .attr("text-anchor", "middle")
        .style("font-size", "11px")
        .style("font-weight", "600")
        .style("fill", "#374151")
        .text(d => d.count > 0 ? d.count : '');
    
    // Add title
    svg.append("text")
        .attr("x", width / 2)
        .attr("y", 20)
        .attr("text-anchor", "middle")
        .style("font-size", "14px")
        .style("font-weight", "600")
        .text("RTT Distribution");
    
    // Add y-axis label
    svg.append("text")
        .attr("transform", "rotate(-90)")
        .attr("x", -height / 2)
        .attr("y", 15)
        .attr("text-anchor", "middle")
        .style("font-size", "12px")
        .style("fill", "#64748b")
        .text("Number of Flows");
    
    // Add legend
    const legend = svg.append("g")
        .attr("transform", `translate(${width - 150}, 40)`);
    
    const legendItems = [
        { label: "Good (<50ms)", color: "#22c55e" },
        { label: "Moderate", color: "#f59e0b" },
        { label: "High (>200ms)", color: "#ef4444" }
    ];
    
    legendItems.forEach((item, i) => {
        const lg = legend.append("g")
            .attr("transform", `translate(0, ${i * 20})`);
        
        lg.append("rect")
            .attr("width", 14)
            .attr("height", 14)
            .attr("fill", item.color)
            .attr("rx", 2);
        
        lg.append("text")
            .attr("x", 20)
            .attr("y", 11)
            .style("font-size", "11px")
            .style("fill", "#374151")
            .text(item.label);
    });
}

// Tooltip helper functions
function showTooltip(event, html) {
    let tooltip = d3.select(".d3-tooltip");
    if (tooltip.empty()) {
        tooltip = d3.select("body")
            .append("div")
            .attr("class", "d3-tooltip")
            .style("position", "absolute")
            .style("background", "rgba(0,0,0,0.8)")
            .style("color", "white")
            .style("padding", "8px 12px")
            .style("border-radius", "4px")
            .style("font-size", "12px")
            .style("pointer-events", "none")
            .style("z-index", "10000");
    }
    tooltip.html(html)
        .style("left", (event.pageX + 10) + "px")
        .style("top", (event.pageY - 10) + "px")
        .style("opacity", 1);
}

function hideTooltip() {
    d3.select(".d3-tooltip")
        .style("opacity", 0);
}
