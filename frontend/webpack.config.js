const webpack = require('webpack');
const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');

module.exports = {
	entry: './src/index.js',
	output: {
		path: path.resolve(__dirname, './dist'),
		filename: 'bundle.js'
	},
	resolve: {
		modules: [path.join(__dirname, "./src"), 'node_modules'],
		extensions: [".elm", ".js"]
	},
	plugins: [
		new HtmlWebpackPlugin({
			template: "./src/index.html"
		}),
		new CleanWebpackPlugin(),
	],
	module: {
		rules: [
			{
				test: /\.elm$/,
				use: [
					{ loader: "elm-reloader" },
					{
						loader: "elm-webpack-loader",
						options: {
							// add Elm's debug overlay to output
							optimize: false,
							debug: false,
							cwd: __dirname
						}
					}
				]
			}, {
				test: /\.(scss)$/,
				use: [
					{
						loader: 'style-loader'
					},
					{
						loader: 'css-loader'
					},
					{
						loader: 'postcss-loader',
						options: {
							postcssOptions: {
								plugins: () => [
									require('autoprefixer')
								]
							}
						}
					},
					{
						loader: 'sass-loader'
					}
				]
			},
			{
				test: /\.woff2?$/,
				type: "asset/resource",
			}

		]
	},
	mode: 'development',

	devServer: {
		hot: true,
		port: 8000,
		host: '0.0.0.0'
	},

};
