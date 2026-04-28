---
layout: page
title: Tags
permalink: /tags/
---

{% assign sorted_tags = site.tags | sort %}

<ul class="tag-cloud">
  {% for tag in sorted_tags %}
  <li><a href="#{{ tag[0] | slugify }}">{{ tag[0] }} <small>({{ tag[1] | size }})</small></a></li>
  {% endfor %}
</ul>

{% for tag in sorted_tags %}
<h2 id="{{ tag[0] | slugify }}">{{ tag[0] }}</h2>
<ul class="tag-posts">
  {% for post in tag[1] %}
  <li>
    <a href="{{ post.url }}">{{ post.title }}</a>
    <small>{{ post.date | date_to_string }}</small>
  </li>
  {% endfor %}
</ul>
{% endfor %}
